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

// Package models contains the database models.
package models

import (
	"database/sql"
	"embed"

	"github.com/pressly/goose/v3"
)

//go:generate bash -xc "go run github.com/kyleconroy/sqlc/cmd/sqlc@latest -f sql/sqlc.yaml generate"

// migrationFS is the filesystem containing the goose migrations.
//
//go:embed sql/**/*
var migrationFS embed.FS

// raftMigrationsPath is the path to the raft db migrations.
var raftMigrationsPath = "sql/migrations"

// schemaVersionTable is the name of the goose schema version table.
var schemaVersionTable = "schema_version"

// gooseDialect is the goose dialect.
var gooseDialect = "sqlite"

func init() {
	goose.SetLogger(goose.NopLogger())
	goose.SetBaseFS(migrationFS)
	goose.SetTableName(schemaVersionTable)
	err := goose.SetDialect(gooseDialect)
	if err != nil {
		panic(err)
	}
}

// MigrateRaftDB migrates the raft database to the latest version.
func MigrateRaftDB(db *sql.DB) error {
	return goose.Up(db, raftMigrationsPath)
}

// GetDBVersion returns the current version of the given database.
func GetDBVersion(db *sql.DB) (int64, error) {
	return goose.GetDBVersion(db)
}
