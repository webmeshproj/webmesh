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
	"fmt"
	"io"
	"time"

	"github.com/hashicorp/raft"
	v1 "gitlab.com/webmesh/api/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
	_ "modernc.org/sqlite"
)

const raftDriverName = "meshqlite"

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
	timeout := s.opts.ApplyTimeout
	if deadline, ok := ctx.Deadline(); ok {
		timeout = time.Until(deadline)
	}
	params, err := toSQLParameters(args)
	if err != nil {
		return nil, fmt.Errorf("to sql parameters: %w", err)
	}
	out, err := proto.Marshal(&v1.RaftLogEntry{
		Type: v1.RaftCommandType_EXECUTE,
		Data: &v1.RaftLogEntry_SqlExec{
			SqlExec: &v1.SQLExec{
				Transaction: true,
				Statement: &v1.SQLStatement{
					Sql:        s.sql,
					Parameters: params,
				},
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("marshal log entry: %w", err)
	}
	f := s.raft.Apply(out, timeout)
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
	timeout := s.opts.ApplyTimeout
	if deadline, ok := ctx.Deadline(); ok {
		timeout = time.Until(deadline)
	}
	params, err := toSQLParameters(args)
	if err != nil {
		return nil, fmt.Errorf("to sql parameters: %w", err)
	}
	out, err := proto.Marshal(&v1.RaftLogEntry{
		Type: v1.RaftCommandType_QUERY,
		Data: &v1.RaftLogEntry_SqlQuery{
			SqlQuery: &v1.SQLQuery{
				Transaction: true,
				Statement: &v1.SQLStatement{
					Sql:        s.sql,
					Parameters: params,
				},
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("marshal log entry: %w", err)
	}
	f := s.raft.Apply(out, timeout)
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
	for i, arg := range args {
		sqlParam := &v1.SQLParameter{Name: arg.Name}
		switch v := arg.Value.(type) {
		case nil:
			sqlParam.Value = nil
		case bool:
			sqlParam.Value = &v1.SQLParameter_Bool{Bool: v}
		case int:
			sqlParam.Value = &v1.SQLParameter_Int64{Int64: int64(v)}
		case int64:
			sqlParam.Value = &v1.SQLParameter_Int64{Int64: v}
		case float64:
			sqlParam.Value = &v1.SQLParameter_Double{Double: v}
		case string:
			sqlParam.Value = &v1.SQLParameter_Str{Str: v}
		case []byte:
			sqlParam.Value = &v1.SQLParameter_Bytes{Bytes: v}
		case time.Time:
			sqlParam.Value = &v1.SQLParameter_Time{Time: timestamppb.New(v)}
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
	if r.resp.GetExec().GetError() != "" {
		return 0, fmt.Errorf("apply log entry data: %s", r.resp.GetExec().GetError())
	}
	return r.resp.GetExec().GetLastInsertId(), nil
}

// RowsAffected returns the number of rows affected by the
// query.
func (r *execResult) RowsAffected() (int64, error) {
	if r.resp.GetExec().GetError() != "" {
		return 0, fmt.Errorf("apply log entry data: %s", r.resp.GetExec().GetError())
	}
	return r.resp.GetExec().GetRowsAffected(), nil
}

type queryResult struct {
	resp  *v1.RaftApplyResponse
	index int64
}

// Columns returns the names of the columns.
func (q *queryResult) Columns() []string {
	return q.resp.GetRows().GetColumns()
}

// Next is called to populate the next row of data into
// the provided slice.
func (q *queryResult) Next(dest []driver.Value) error {
	if q.resp.GetRows().GetError() != "" {
		return fmt.Errorf("apply log entry data: %s", q.resp.GetRows().GetError())
	}
	if q.index >= int64(len(q.resp.GetRows().GetValues())) {
		return io.EOF
	}
	for i, v := range q.resp.GetRows().GetValues()[q.index].Values {
		if v == nil {
			dest[i] = nil
			continue
		}
		switch val := v.Value.(type) {
		case *v1.SQLParameter_Int64:
			dest[i] = val.Int64
		case *v1.SQLParameter_Double:
			dest[i] = val.Double
		case *v1.SQLParameter_Bool:
			dest[i] = val.Bool
		case *v1.SQLParameter_Str:
			dest[i] = val.Str
		case *v1.SQLParameter_Bytes:
			dest[i] = val.Bytes
		case *v1.SQLParameter_Time:
			dest[i] = val.Time.AsTime()
		default:
			return fmt.Errorf("unsupported parameter type: %T", val)
		}
	}
	q.index++
	return nil
}

// ColumnTypeDatabaseTypeName returns the database system type.
func (q *queryResult) ColumnTypeDatabaseTypeName(index int) string {
	return q.resp.GetRows().GetTypes()[index]
}

// Close closes the rows iterator.
func (q *queryResult) Close() error {
	return nil
}
