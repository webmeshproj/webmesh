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

// Package plugindb contains a SQL driver for running data queries over a Plugin
// Query stream.
package plugindb

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"sync"

	"github.com/google/uuid"
	"github.com/mattn/go-sqlite3"
	v1 "github.com/webmeshproj/api/v1"

	"github.com/webmeshproj/node/pkg/meshdb/models"
	"github.com/webmeshproj/node/pkg/meshdb/raftlogs"
)

// Open opens a new database connection to a plugin query stream.
func Open(srv v1.Plugin_InjectQuerierServer) (*sql.DB, error) {
	drvId, err := uuid.NewRandom()
	if err != nil {
		return nil, fmt.Errorf("generate uuid: %w", err)
	}
	db, err := sql.Open("sqlite3", fmt.Sprintf("file:%s?mode=memory", drvId))
	if err != nil {
		return nil, fmt.Errorf("open sqlite3: %w", err)
	}
	if err := models.MigrateDB(db); err != nil {
		defer db.Close()
		return nil, fmt.Errorf("migrate db: %w", err)
	}
	sql.Register(drvId.String(), &pluginDB{srv: srv, models: db})
	return sql.Open(drvId.String(), "")
}

type pluginDB struct {
	srv    v1.Plugin_InjectQuerierServer
	models *sql.DB
	// TODO: Add a multiplexer to allow multiple queries at once?
	mu sync.Mutex
}

func (db *pluginDB) Open(_ string) (driver.Conn, error) {
	return db, nil
}

// OpenConnector returns a new connector that is backed by the Raft log.
func (db *pluginDB) OpenConnector(_ string) (driver.Connector, error) {
	return db, nil
}

// Connect returns a new connection that is backed by the Raft log.
func (db *pluginDB) Connect(ctx context.Context) (driver.Conn, error) {
	return db, nil
}

// Driver returns the driver.
func (db *pluginDB) Driver() driver.Driver {
	return db
}

// Transactions are not supported.

// Begin starts a new transaction.
func (db *pluginDB) Begin() (driver.Tx, error) {
	return db, nil
}

// Commit commits the transaction.
func (db *pluginDB) Commit() error {
	return nil
}

// Rollback rolls back the transaction.
func (db *pluginDB) Rollback() error {
	return nil
}

// Close closes the connection.
func (db *pluginDB) Close() error {
	return db.models.Close()
}

// Prepare returns a prepared statement.
func (db *pluginDB) Prepare(query string) (driver.Stmt, error) {
	return db.PrepareContext(context.Background(), query)
}

// PrepareContext returns a new statement that is backed by the Raft log.
func (db *pluginDB) PrepareContext(ctx context.Context, query string) (driver.Stmt, error) {
	c, err := db.models.Conn(ctx)
	if err != nil {
		return nil, fmt.Errorf("get conn: %w", err)
	}
	defer c.Close()
	var numInput int
	err = c.Raw(func(driverConn interface{}) error {
		conn, ok := driverConn.(*sqlite3.SQLiteConn)
		if !ok {
			return fmt.Errorf("raw conn is not sqlite3")
		}
		stmt, err := conn.PrepareContext(ctx, query)
		if err != nil {
			return fmt.Errorf("prepare: %w", err)
		}
		defer stmt.Close()
		sqlstmt, ok := stmt.(*sqlite3.SQLiteStmt)
		if !ok {
			return fmt.Errorf("stmt is not sqlite3")
		}
		numInput = sqlstmt.NumInput()
		return nil
	})
	return &pluginStatement{db, query, numInput}, err
}

type pluginStatement struct {
	db       *pluginDB
	sql      string
	numInput int
}

// NumInput is a noop. It is handled during parsing.
func (s *pluginStatement) NumInput() int {
	return s.numInput
}

// Exec executes the statement with the given arguments.
func (s *pluginStatement) Exec(args []driver.Value) (driver.Result, error) {
	return s.ExecContext(context.Background(), raftlogs.ValuesToNamedValues(args))
}

// Query executes the statement with the given arguments.
func (s *pluginStatement) Query(args []driver.Value) (driver.Rows, error) {
	return s.QueryContext(context.Background(), raftlogs.ValuesToNamedValues(args))
}

func (s *pluginStatement) ExecContext(ctx context.Context, args []driver.NamedValue) (driver.Result, error) {
	return nil, errors.New("not implemented")
}

func (s *pluginStatement) QueryContext(ctx context.Context, args []driver.NamedValue) (driver.Rows, error) {
	s.db.mu.Lock()
	defer s.db.mu.Unlock()
	id, err := uuid.NewRandom()
	if err != nil {
		return nil, fmt.Errorf("generate uuid: %w", err)
	}
	params, err := raftlogs.NamedValuesToSQLParameters(args)
	if err != nil {
		return nil, fmt.Errorf("named values to sql parameters: %w", err)
	}
	req := &v1.PluginSQLQuery{
		Id: id.String(),
		Query: &v1.SQLQuery{
			Statement: &v1.SQLStatement{
				Sql:        s.sql,
				Parameters: params,
			},
		},
	}
	err = s.db.srv.Send(req)
	if err != nil {
		return nil, fmt.Errorf("send query: %w", err)
	}
	res, err := s.db.srv.Recv()
	if err != nil {
		return nil, fmt.Errorf("receive query result: %w", err)
	}
	if res.GetError() != "" {
		return nil, errors.New(res.GetError())
	}
	return raftlogs.NewRows(res.GetResult()), nil
}

// Close closes the statement.
func (s *pluginStatement) Close() error {
	return nil
}
