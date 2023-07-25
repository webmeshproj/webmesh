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

// Package meshdb contains the schemas, generated code, and interfaces for
// interacting with the mesh database.
package meshdb

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/google/uuid"
	"github.com/hashicorp/raft"
	_ "github.com/mattn/go-sqlite3"

	"github.com/webmeshproj/node/pkg/meshdb/models"
	"github.com/webmeshproj/node/pkg/net/wireguard"
	"github.com/webmeshproj/node/pkg/plugins"
	"github.com/webmeshproj/node/pkg/storage"
)

// Store is the interface for interacting with the mesh database. It is a reduced
// version of the store.Store interface.
type Store interface {
	// ID returns the ID of the node.
	ID() string
	// DB returns a DB interface for use by the application.
	DB() DB
	// Storage returns a storage interface for use by the application.
	Storage() storage.Storage
	// Raft returns the underlying Raft database.
	Raft() *raft.Raft
	// Leader returns the current Raft leader.
	Leader() (raft.ServerID, error)
	// IsLeader returns whether the current node is the Raft leader.
	IsLeader() bool
	// Plugins returns the plugins for the current node.
	Plugins() plugins.Manager
	// WireGuard returns the Wireguard interface. Note that the returned value
	// may be nil if the store is not open.
	WireGuard() wireguard.Interface
}

// DB is the interface for interacting with the mesh database.
type DB interface {
	// Read returns a database querier for read operations.
	Read() DBTX
	// Write returns a database querier for write operations.
	Write() DBTX
}

// DBTX is the interface for interacting with a database transaction.
type DBTX interface {
	ExecContext(context.Context, string, ...interface{}) (sql.Result, error)
	PrepareContext(context.Context, string) (*sql.Stmt, error)
	QueryContext(context.Context, string, ...interface{}) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...interface{}) *sql.Row
}

// New creates a new mesh database with the given *sql.DB. It is intended
// for use by plugins.
func New(db *sql.DB) DB {
	return &simpleDB{db: db}
}

// NewTestDB returns a new in-memory database for testing. Read and Write
// operations are performed on the same database.
func NewTestDB() (DB, func(), error) {
	dataPath := fmt.Sprintf("file:%s?mode=memory&cache=shared&_foreign_keys=on&_case_sensitive_like=on&synchronous=full", uuid.NewString())
	db, err := sql.Open("sqlite3", dataPath)
	if err != nil {
		return nil, nil, fmt.Errorf("open database: %w", err)
	}
	err = models.MigrateDB(db)
	if err != nil {
		defer db.Close()
		return nil, nil, fmt.Errorf("migrate database: %w", err)
	}
	return &simpleDB{db: db}, func() { db.Close() }, nil
}

type simpleDB struct {
	db *sql.DB
}

func (t *simpleDB) Read() DBTX {
	return t.db
}

func (t *simpleDB) Write() DBTX {
	return t.db
}
