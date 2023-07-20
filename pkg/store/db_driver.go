/*
Copyright 2023 Avi Zimmerman <avi.zimmerman@gmail.com>

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
	"errors"
	"fmt"
	"time"

	"github.com/golang/snappy"
	"github.com/hashicorp/raft"
	v1 "github.com/webmeshproj/api/v1"
	"google.golang.org/protobuf/proto"

	"github.com/webmeshproj/node/pkg/meshdb/raftlogs"
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
	return s.ExecContext(context.Background(), raftlogs.ValuesToNamedValues(args))
}

// Query applies the query to the Raft log.
func (s *raftDBStatement) Query(args []driver.Value) (driver.Rows, error) {
	return s.QueryContext(context.Background(), raftlogs.ValuesToNamedValues(args))
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
	params, err := raftlogs.NamedValuesToSQLParameters(args)
	if err != nil {
		return nil, fmt.Errorf("named values to sql parameters: %w", err)
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
	data, err := proto.Marshal(logEntry)
	if err == nil {
		data = snappy.Encode(nil, data)
	}
	if err != nil {
		return nil, fmt.Errorf("encode log entry: %w", err)
	}
	f := s.raft.Apply(data, timeout)
	if err := f.Error(); err != nil {
		if errors.Is(err, raft.ErrNotLeader) {
			return nil, ErrNotLeader
		}
		return nil, fmt.Errorf("apply log entry: %w", err)
	}
	resp := f.Response().(*v1.RaftApplyResponse)
	if resp.GetError() != "" {
		return nil, fmt.Errorf("apply log entry data: %s", resp.GetError())
	}
	return raftlogs.NewResult(resp.GetExecResult()), nil
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
	params, err := raftlogs.NamedValuesToSQLParameters(args)
	if err != nil {
		return nil, fmt.Errorf("named values to sql parameters: %w", err)
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
	data, err := proto.Marshal(logEntry)
	if err == nil {
		data = snappy.Encode(nil, data)
	}
	if err != nil {
		return nil, fmt.Errorf("encode log entry: %w", err)
	}
	f := s.raft.Apply(data, timeout)
	if err := f.Error(); err != nil {
		if errors.Is(err, raft.ErrNotLeader) {
			return nil, ErrNotLeader
		}
		return nil, fmt.Errorf("apply log entry: %w", err)
	}
	resp := f.Response().(*v1.RaftApplyResponse)
	if resp.GetError() != "" {
		return nil, fmt.Errorf("apply log entry data: %s", resp.GetError())
	}
	return raftlogs.NewRows(resp.GetQueryResult()), nil
}
