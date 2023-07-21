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

package raftlogs

import (
	"database/sql"
	"fmt"

	"github.com/mattn/go-sqlite3"

	"github.com/webmeshproj/node/pkg/context"
)

// IsReadOnlyStatement returns true if the SQL statement is a read-only statement.
func IsReadOnlyStatement(ctx context.Context, db *sql.DB, statement string) (bool, error) {
	if statement == "" {
		return false, nil
	}
	conn, err := db.Conn(ctx)
	if err != nil {
		return false, err
	}
	defer conn.Close()
	var readonly bool
	err = conn.Raw(func(driverConn interface{}) error {
		conn, ok := driverConn.(*sqlite3.SQLiteConn)
		if !ok {
			return fmt.Errorf("raw conn is not sqlite3")
		}
		stmt, err := conn.PrepareContext(ctx, statement)
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
