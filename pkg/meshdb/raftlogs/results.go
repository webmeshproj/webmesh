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
	"database/sql/driver"
	"fmt"
	"io"

	v1 "github.com/webmeshproj/api/v1"
)

// NewResult returns a new driver.Result from the given RaftApplyResponse.
func NewResult(res *v1.SQLExecResult) driver.Result {
	return &execResult{res}
}

type execResult struct {
	res *v1.SQLExecResult
}

// LastInsertId returns the database's auto-generated ID
// after, for example, an INSERT into a table with primary
// key.
func (r *execResult) LastInsertId() (int64, error) {
	return r.res.GetLastInsertId(), nil
}

// RowsAffected returns the number of rows affected by the
// query.
func (r *execResult) RowsAffected() (int64, error) {
	return r.res.GetRowsAffected(), nil
}

// NewRows returns a new driver.Rows from the given RaftApplyResponse.
func NewRows(res *v1.SQLQueryResult) driver.Rows {
	return &queryResult{res, 0}
}

type queryResult struct {
	res   *v1.SQLQueryResult
	index int64
}

// Columns returns the names of the columns.
func (q *queryResult) Columns() []string {
	return q.res.GetColumns()
}

// Next is called to populate the next row of data into
// the provided slice.
func (q *queryResult) Next(dest []driver.Value) error {
	if q.index >= int64(len(q.res.GetValues())) {
		return io.EOF
	}
	var err error
	for i, v := range q.res.GetValues()[q.index].Values {
		dest[i], err = SQLParameterToDriverValue(v)
		if err != nil {
			return fmt.Errorf("sql parameter to driver value: %w", err)
		}
	}
	q.index++
	return nil
}

// ColumnTypeDatabaseTypeName returns the database system type.
func (q *queryResult) ColumnTypeDatabaseTypeName(index int) string {
	return q.res.GetTypes()[index]
}

// Close closes the rows iterator.
func (q *queryResult) Close() error {
	return nil
}
