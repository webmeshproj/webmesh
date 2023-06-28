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
	"database/sql"
	"fmt"
	"sync"

	"github.com/mattn/go-sqlite3"
	"golang.org/x/exp/slog"
)

var ErrStatementNotReadOnly = fmt.Errorf("statement is not read-only")

type roLockableDB struct {
	*sql.DB
	mux sync.Locker
}

func (d *roLockableDB) ExecContext(ctx context.Context, stmt string, args ...any) (sql.Result, error) {
	d.mux.Lock()
	defer d.mux.Unlock()
	readonly, err := d.isReadonly(ctx, stmt)
	if err != nil {
		return nil, fmt.Errorf("exec, check readonly: %w", err)
	}
	if !readonly {
		return nil, ErrStatementNotReadOnly
	}
	return d.DB.ExecContext(ctx, stmt, args...)
}

func (d *roLockableDB) QueryContext(ctx context.Context, stmt string, args ...any) (*sql.Rows, error) {
	d.mux.Lock()
	defer d.mux.Unlock()
	readonly, err := d.isReadonly(ctx, stmt)
	if err != nil {
		return nil, fmt.Errorf("query, check readonly: %w", err)
	}
	if !readonly {
		return nil, ErrStatementNotReadOnly
	}
	return d.DB.QueryContext(ctx, stmt, args...)
}

func (d *roLockableDB) QueryRowContext(ctx context.Context, stmt string, args ...any) *sql.Row {
	d.mux.Lock()
	defer d.mux.Unlock()
	readonly, err := d.isReadonly(ctx, stmt)
	if err != nil {
		// send a bad query
		slog.Default().Error("query, check readonly", slog.String("error", err.Error()))
		return d.DB.QueryRowContext(ctx, "SELECT 1 WHERE 0")
	} else if !readonly {
		// send a bad query
		slog.Default().Error("query, check readonly", slog.String("error", ErrStatementNotReadOnly.Error()))
		return d.DB.QueryRowContext(ctx, "SELECT 1 WHERE 0")
	}
	return d.DB.QueryRowContext(ctx, stmt, args...)
}

func (d *roLockableDB) isReadonly(ctx context.Context, stmt string) (bool, error) {
	if stmt == "" {
		return false, nil
	}
	c, err := d.DB.Conn(ctx)
	if err != nil {
		return false, fmt.Errorf("acquire conn: %w", err)
	}
	defer c.Close()
	var readonly bool
	err = c.Raw(func(driverConn interface{}) error {
		conn, ok := driverConn.(*sqlite3.SQLiteConn)
		if !ok {
			return fmt.Errorf("raw conn is not sqlite3")
		}
		stmt, err := conn.PrepareContext(ctx, stmt)
		if err != nil {
			return fmt.Errorf("prepare: %w", err)
		}
		defer stmt.Close()
		sqlstmt, ok := stmt.(*sqlite3.SQLiteStmt)
		if !ok {
			return fmt.Errorf("stmt is not sqlite3")
		}
		readonly = sqlstmt.Readonly()
		return nil
	})
	return readonly, err
}
