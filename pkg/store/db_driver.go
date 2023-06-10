/*
Copyright 2023.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package store

import (
	"context"
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/golang/snappy"
	"github.com/hashicorp/raft"
	_ "github.com/mattn/go-sqlite3"
	v1 "github.com/webmeshproj/api/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// raftDBDriver is a driver that is backed by the Raft log.
type raftDBDriver struct {
	*store
}

// Open returns a new connection that is backed by the Raft log.
func (d *raftDBDriver) Open(_ string) (driver.Conn, error) {
	return &raftDBConn{d}, nil
}

// OpenConnector returns a new connector that is backed by the Raft log.
func (d *raftDBDriver) OpenConnector(_ string) (driver.Connector, error) {
	return &raftConnector{d}, nil
}

// raftConnector is a connector that is backed by the Raft log.
type raftConnector struct {
	*raftDBDriver
}

// Connect returns a new connection that is backed by the Raft log.
func (d *raftConnector) Connect(ctx context.Context) (driver.Conn, error) {
	return &raftDBConn{d.raftDBDriver}, nil
}

// Driver returns the driver.
func (d *raftConnector) Driver() driver.Driver {
	return d.raftDBDriver
}

// raftDBConn is a connection that is backed by the Raft log.
type raftDBConn struct {
	*raftDBDriver
}

// Prepare returns a new statement that is backed by the Raft log.
func (c *raftDBConn) Prepare(query string) (driver.Stmt, error) {
	if !c.IsLeader() {
		return nil, ErrNotLeader
	}
	return &raftDBStatement{c.raftDBDriver, query}, nil
}

// PrepareContext returns a new statement that is backed by the Raft log.
func (c *raftDBConn) PrepareContext(ctx context.Context, query string) (driver.Stmt, error) {
	if !c.IsLeader() {
		return nil, ErrNotLeader
	}
	return &raftDBStatement{c.raftDBDriver, query}, nil
}

// Ping pings the Raft log by verifying we are the leader.
func (c *raftDBConn) Ping(ctx context.Context) error {
	f := c.raft.VerifyLeader()
	err := make(chan error, 1)
	go func() {
		err <- f.Error()
	}()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-err:
		return err
	}
}

// Begin starts a transaction. Everything is a transaction in the Raft
// log for now, but we provide a Begin method for completeness.
// TODO: Potentially use this to batch queries in the raft log.
// Would need to be able to parse read-only statements out to serve them
// locally.
func (c *raftDBConn) Begin() (driver.Tx, error) {
	return c, nil
}

// Close is a noop because it is handled by the Raft log.
func (c *raftDBConn) Close() error {
	return nil
}

// Commit is a noop because it is handled by the Raft log.
func (c *raftDBConn) Commit() error {
	return nil
}

// Rollback is a noop because it is handled by the Raft log.
func (c *raftDBConn) Rollback() error {
	return nil
}

// raftDBStatement is a statement that is backed by the Raft log.
type raftDBStatement struct {
	*raftDBDriver
	sql string
}

// Close is a noop because it is handled by the Raft log.
func (s *raftDBStatement) Close() error {
	return nil
}

// NumInput is a noop because it is handled by the Raft log.
func (s *raftDBStatement) NumInput() int {
	return -1
}

// Commit is a noop because it is handled by the Raft log.
func (s *raftDBStatement) Commit() error {
	return nil
}

// Rollback is a noop because it is handled by the Raft log.
func (s *raftDBStatement) Rollback() error {
	return nil
}

// Exec applies the query to the Raft log.
func (s *raftDBStatement) Exec(args []driver.Value) (driver.Result, error) {
	return s.ExecContext(context.Background(), toNamedValues(args))
}

// Query applies the query to the Raft log.
func (s *raftDBStatement) Query(args []driver.Value) (driver.Rows, error) {
	return s.QueryContext(context.Background(), toNamedValues(args))
}

// ExecContext applies the query to the Raft log.
func (s *raftDBStatement) ExecContext(ctx context.Context, args []driver.NamedValue) (driver.Result, error) {
	if !s.IsLeader() {
		return nil, ErrNotLeader
	}
	if !s.Ready() {
		return nil, ErrNotReady
	}
	timeout := s.opts.Raft.ApplyTimeout
	if deadline, ok := ctx.Deadline(); ok {
		timeout = time.Until(deadline)
	}
	params, err := toSQLParameters(args)
	if err != nil {
		return nil, fmt.Errorf("to sql parameters: %w", err)
	}
	logEntry := &v1.RaftLogEntry{
		Type: v1.RaftCommandType_EXECUTE,
		SqlExec: &v1.SQLExec{
			Transaction: true,
			Statement: &v1.SQLStatement{
				Sql:        s.sql,
				Parameters: params,
			},
		},
	}
	var data []byte
	switch s.raftLogFormat {
	case RaftLogFormatJSON:
		data, err = json.Marshal(logEntry)
	case RaftLogFormatProtobuf:
		data, err = proto.Marshal(logEntry)
	case RaftLogFormatProtobufSnappy:
		data, err = proto.Marshal(logEntry)
		if err == nil {
			data = snappy.Encode(nil, data)
		}
	default:
		err = fmt.Errorf("unknown raft log format: %s", s.raftLogFormat)
	}
	if err != nil {
		return nil, fmt.Errorf("marshal log entry: %w", err)
	}
	f := s.raft.Apply(data, timeout)
	if f.Error() != nil {
		if f.Error() == raft.ErrNotLeader {
			return nil, ErrNotLeader
		}
		return nil, fmt.Errorf("apply log entry: %w", f.Error())
	}
	s.dataAppliedIndex.Store(f.Index())
	resp := f.Response().(*v1.RaftApplyResponse)
	if resp.GetError() != "" {
		return nil, fmt.Errorf("apply log entry data: %s", resp.GetError())
	}
	if resp.GetExecResult().GetError() != "" {
		return nil, fmt.Errorf("execute statement: %s", resp.GetExecResult().GetError())
	}
	return &execResult{resp}, nil
}

// QueryContext applies the query to the Raft log.
func (s *raftDBStatement) QueryContext(ctx context.Context, args []driver.NamedValue) (driver.Rows, error) {
	if !s.IsLeader() {
		return nil, ErrNotLeader
	}
	if !s.Ready() {
		return nil, ErrNotReady
	}
	timeout := s.opts.Raft.ApplyTimeout
	if deadline, ok := ctx.Deadline(); ok {
		timeout = time.Until(deadline)
	}
	params, err := toSQLParameters(args)
	if err != nil {
		return nil, fmt.Errorf("to sql parameters: %w", err)
	}
	logEntry := &v1.RaftLogEntry{
		Type: v1.RaftCommandType_QUERY,
		SqlQuery: &v1.SQLQuery{
			Transaction: true,
			Statement: &v1.SQLStatement{
				Sql:        s.sql,
				Parameters: params,
			},
		},
	}
	var data []byte
	switch s.raftLogFormat {
	case RaftLogFormatJSON:
		data, err = protojson.Marshal(logEntry)
	case RaftLogFormatProtobuf:
		data, err = proto.Marshal(logEntry)
	case RaftLogFormatProtobufSnappy:
		data, err = proto.Marshal(logEntry)
		if err == nil {
			data = snappy.Encode(nil, data)
		}
	default:
		err = fmt.Errorf("unknown raft log format: %s", s.raftLogFormat)
	}
	if err != nil {
		return nil, fmt.Errorf("marshal log entry: %w", err)
	}
	f := s.raft.Apply(data, timeout)
	if f.Error() != nil {
		if f.Error() == raft.ErrNotLeader {
			return nil, ErrNotLeader
		}
		return nil, fmt.Errorf("apply log entry: %w", f.Error())
	}
	s.dataAppliedIndex.Store(f.Index())
	resp := f.Response().(*v1.RaftApplyResponse)
	if resp.GetError() != "" {
		return nil, fmt.Errorf("apply log entry data: %s", resp.GetError())
	}
	if resp.GetQueryResult().GetError() != "" {
		return nil, fmt.Errorf("query: %s", resp.GetQueryResult().GetError())
	}
	return &queryResult{resp, 0}, nil
}

func toNamedValues(args []driver.Value) []driver.NamedValue {
	named := make([]driver.NamedValue, len(args))
	for i, arg := range args {
		named[i] = driver.NamedValue{
			Ordinal: i + 1,
			Value:   arg,
		}
	}
	return named
}

func toSQLParameters(args []driver.NamedValue) ([]*v1.SQLParameter, error) {
	params := make([]*v1.SQLParameter, len(args))
	for i, argz := range args {
		arg := argz
		sqlParam := &v1.SQLParameter{Name: arg.Name}
		switch v := arg.Value.(type) {
		case nil:
			sqlParam.Type = v1.SQLParameterType_SQL_PARAM_NULL
		case bool:
			sqlParam.Type = v1.SQLParameterType_SQL_PARAM_BOOL
			sqlParam.Bool = v
		case int:
			sqlParam.Type = v1.SQLParameterType_SQL_PARAM_INT64
			sqlParam.Int64 = int64(v)
		case int64:
			sqlParam.Type = v1.SQLParameterType_SQL_PARAM_INT64
			sqlParam.Int64 = v
		case float64:
			sqlParam.Type = v1.SQLParameterType_SQL_PARAM_DOUBLE
			sqlParam.Double = v
		case string:
			sqlParam.Type = v1.SQLParameterType_SQL_PARAM_STRING
			sqlParam.Str = v
		case []byte:
			sqlParam.Type = v1.SQLParameterType_SQL_PARAM_BYTES
			sqlParam.Bytes = v
		case time.Time:
			sqlParam.Type = v1.SQLParameterType_SQL_PARAM_TIME
			sqlParam.Time = timestamppb.New(v)
		default:
			return nil, fmt.Errorf("unsupported parameter type: %T", v)
		}
		params[i] = sqlParam
	}
	return params, nil
}

type execResult struct {
	resp *v1.RaftApplyResponse
}

// LastInsertId returns the database's auto-generated ID
// after, for example, an INSERT into a table with primary
// key.
func (r *execResult) LastInsertId() (int64, error) {
	if r.resp.GetExecResult().GetError() != "" {
		return 0, fmt.Errorf("apply log entry data: %s", r.resp.GetExecResult().GetError())
	}
	return r.resp.GetExecResult().GetLastInsertId(), nil
}

// RowsAffected returns the number of rows affected by the
// query.
func (r *execResult) RowsAffected() (int64, error) {
	if r.resp.GetExecResult().GetError() != "" {
		return 0, fmt.Errorf("apply log entry data: %s", r.resp.GetExecResult().GetError())
	}
	return r.resp.GetExecResult().GetRowsAffected(), nil
}

type queryResult struct {
	resp  *v1.RaftApplyResponse
	index int64
}

// Columns returns the names of the columns.
func (q *queryResult) Columns() []string {
	return q.resp.GetQueryResult().GetColumns()
}

// Next is called to populate the next row of data into
// the provided slice.
func (q *queryResult) Next(dest []driver.Value) error {
	if q.resp.GetQueryResult().GetError() != "" {
		return fmt.Errorf("apply log entry data: %s", q.resp.GetQueryResult().GetError())
	}
	if q.index >= int64(len(q.resp.GetQueryResult().GetValues())) {
		return io.EOF
	}
	for i, v := range q.resp.GetQueryResult().GetValues()[q.index].Values {
		if v == nil {
			dest[i] = nil
			continue
		}

		switch v.Type {
		case v1.SQLParameterType_SQL_PARAM_INT64:
			dest[i] = v.GetInt64()
		case v1.SQLParameterType_SQL_PARAM_DOUBLE:
			dest[i] = v.GetDouble()
		case v1.SQLParameterType_SQL_PARAM_BOOL:
			dest[i] = v.GetBool()
		case v1.SQLParameterType_SQL_PARAM_BYTES:
			dest[i] = v.GetBytes()
		case v1.SQLParameterType_SQL_PARAM_STRING:
			dest[i] = v.GetStr()
		case v1.SQLParameterType_SQL_PARAM_TIME:
			dest[i] = v.GetTime().AsTime()
		case v1.SQLParameterType_SQL_PARAM_NULL:
			dest[i] = nil
		default:
			return fmt.Errorf("unsupported type: %T", v.GetType())
		}
	}
	q.index++
	return nil
}

// ColumnTypeDatabaseTypeName returns the database system type.
func (q *queryResult) ColumnTypeDatabaseTypeName(index int) string {
	return q.resp.GetQueryResult().GetTypes()[index]
}

// Close closes the rows iterator.
func (q *queryResult) Close() error {
	return nil
}
