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
	"sync"
)

type lockableDB struct {
	*sql.DB
	mux sync.Locker
}

func (d *lockableDB) ExecContext(ctx context.Context, stmt string, args ...any) (sql.Result, error) {
	d.mux.Lock()
	defer d.mux.Unlock()
	return d.DB.ExecContext(ctx, stmt, args...)
}

func (d *lockableDB) QueryContext(ctx context.Context, stmt string, args ...any) (*sql.Rows, error) {
	d.mux.Lock()
	defer d.mux.Unlock()
	return d.DB.QueryContext(ctx, stmt, args...)
}

func (d *lockableDB) QueryRowContext(ctx context.Context, stmt string, args ...any) *sql.Row {
	d.mux.Lock()
	defer d.mux.Unlock()
	return d.DB.QueryRowContext(ctx, stmt, args...)
}
