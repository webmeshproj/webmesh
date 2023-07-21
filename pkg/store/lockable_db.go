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
	"database/sql"
	"fmt"
	"sync"

	"golang.org/x/exp/slog"

	"github.com/webmeshproj/node/pkg/context"
	"github.com/webmeshproj/node/pkg/meshdb/raftlogs"
)

var ErrStatementNotReadOnly = fmt.Errorf("statement is not read-only")

type roLockableDB struct {
	db *sql.DB
	mu sync.Locker
}

func (d *roLockableDB) ExecContext(ctx context.Context, stmt string, args ...any) (sql.Result, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	readonly, err := raftlogs.IsReadOnlyStatement(ctx, d.db, stmt)
	if err != nil {
		return nil, fmt.Errorf("exec, check readonly: %w", err)
	}
	if !readonly {
		return nil, ErrStatementNotReadOnly
	}
	return d.db.ExecContext(ctx, stmt, args...)
}

func (d *roLockableDB) PrepareContext(ctx context.Context, stmt string) (*sql.Stmt, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	readonly, err := raftlogs.IsReadOnlyStatement(ctx, d.db, stmt)
	if err != nil {
		return nil, fmt.Errorf("prepare, check readonly: %w", err)
	}
	if !readonly {
		return nil, ErrStatementNotReadOnly
	}
	return d.db.PrepareContext(ctx, stmt)
}

func (d *roLockableDB) QueryContext(ctx context.Context, stmt string, args ...any) (*sql.Rows, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	readonly, err := raftlogs.IsReadOnlyStatement(ctx, d.db, stmt)
	if err != nil {
		return nil, fmt.Errorf("query, check readonly: %w", err)
	}
	if !readonly {
		return nil, ErrStatementNotReadOnly
	}
	return d.db.QueryContext(ctx, stmt, args...)
}

func (d *roLockableDB) QueryRowContext(ctx context.Context, stmt string, args ...any) *sql.Row {
	d.mu.Lock()
	defer d.mu.Unlock()
	readonly, err := raftlogs.IsReadOnlyStatement(ctx, d.db, stmt)
	if err != nil {
		// send a bad query
		context.LoggerFrom(ctx).Error("query row, check readonly", slog.String("error", err.Error()))
		return d.db.QueryRowContext(ctx, "SELECT 1 WHERE 0")
	} else if !readonly {
		// send a bad query
		context.LoggerFrom(ctx).Error("query row, check readonly", slog.String("error", ErrStatementNotReadOnly.Error()))
		return d.db.QueryRowContext(ctx, "SELECT 1 WHERE 0")
	}
	return d.db.QueryRowContext(ctx, stmt, args...)
}
