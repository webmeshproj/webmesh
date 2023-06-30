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
	"context"
	"database/sql"
	"testing"

	_ "github.com/mattn/go-sqlite3"
	v1 "github.com/webmeshproj/api/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

func TestApplyRaftLogs(t *testing.T) {
	t.Parallel()

	db, err := sql.Open("sqlite3", "file:raft-log-apply-test?mode=memory&cache=shared")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	// Create a test table and populate it with some data.
	if _, err := db.Exec(`
		CREATE TABLE test (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL
		);
	`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`
		INSERT INTO test (name) VALUES
			("foo"),
			("bar"),
			("baz");
	`); err != nil {
		t.Fatal(err)
	}

	tc := []struct {
		name  string
		entry *v1.RaftLogEntry
		want  *ApplyResponse
	}{
		{
			name: "unknown command",
			entry: &v1.RaftLogEntry{
				Type: -1,
			},
			want: &ApplyResponse{
				Error: "unknown command type: -1",
			},
		},
		{
			name: "malformed query",
			entry: &v1.RaftLogEntry{
				Type: v1.RaftCommandType_QUERY,
				SqlQuery: &v1.SQLQuery{
					Transaction: true,
					Statement: &v1.SQLStatement{
						Sql:        "SELECT * FROM non_existent_table",
						Parameters: []*v1.SQLParameter{},
					},
				},
			},
			want: &ApplyResponse{
				Error: "query: no such table: non_existent_table",
			},
		},
		{
			name: "simple query",
			entry: &v1.RaftLogEntry{
				Type: v1.RaftCommandType_QUERY,
				SqlQuery: &v1.SQLQuery{
					Transaction: true,
					Statement: &v1.SQLStatement{
						Sql:        "SELECT * FROM test ORDER BY id ASC",
						Parameters: []*v1.SQLParameter{},
					},
				},
			},
			want: &ApplyResponse{
				QueryResult: &v1.SQLQueryResult{
					Columns: []string{"id", "name"},
					Types:   []string{"INTEGER", "TEXT"},
					Values: []*v1.SQLValues{
						{
							Values: []*v1.SQLParameter{
								{Type: v1.SQLParameterType_SQL_PARAM_INT64, Int64: 1},
								{Type: v1.SQLParameterType_SQL_PARAM_STRING, Str: "foo"},
							},
						},
						{
							Values: []*v1.SQLParameter{
								{Type: v1.SQLParameterType_SQL_PARAM_INT64, Int64: 2},
								{Type: v1.SQLParameterType_SQL_PARAM_STRING, Str: "bar"},
							},
						},
						{
							Values: []*v1.SQLParameter{
								{Type: v1.SQLParameterType_SQL_PARAM_INT64, Int64: 3},
								{Type: v1.SQLParameterType_SQL_PARAM_STRING, Str: "baz"},
							},
						},
					},
				},
			},
		},
		{
			name: "simple exec",
			entry: &v1.RaftLogEntry{
				Type: v1.RaftCommandType_EXECUTE,
				SqlExec: &v1.SQLExec{
					Transaction: true,
					Statement: &v1.SQLStatement{
						Sql: "INSERT INTO test (name) VALUES (?)",
						Parameters: []*v1.SQLParameter{
							{Type: v1.SQLParameterType_SQL_PARAM_STRING, Str: "qux"},
						},
					},
				},
			},
			want: &ApplyResponse{
				ExecResult: &v1.SQLExecResult{
					LastInsertId: 4,
					RowsAffected: 1,
				},
			},
		},
	}

	for _, tt := range tc {
		t.Run(tt.name, func(t *testing.T) {
			got := (*ApplyResponse)(Apply(context.Background(), db, tt.entry))
			if !tt.want.DeepEqual(got) {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

type ApplyResponse v1.RaftApplyResponse

func (a *ApplyResponse) DeepEqual(b *ApplyResponse) bool {
	if a.Error != b.Error {
		return false
	}
	if a.QueryResult != nil {
		if b.QueryResult == nil {
			return false
		}
		return protoMessagesEqual(a.QueryResult, b.QueryResult)
	}
	if a.ExecResult != nil {
		if b.ExecResult == nil {
			return false
		}
		return protoMessagesEqual(a.ExecResult, b.ExecResult)
	}
	return true
}

func protoMessagesEqual(a, b proto.Message) bool {
	abytes, err := protojson.Marshal(a)
	if err != nil {
		return false
	}
	bbytes, err := protojson.Marshal(b)
	if err != nil {
		return false
	}
	return string(abytes) == string(bbytes)
}
