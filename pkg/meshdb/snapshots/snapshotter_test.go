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

package snapshots

import (
	"bytes"
	"context"
	"database/sql"
	"io"
	"testing"
)

func TestSnapshotter(t *testing.T) {
	t.Parallel()

	db, err := sql.Open("sqlite3", "file:snapshotter-test?mode=memory&cache=shared")
	if err != nil {
		t.Fatal(err)
	}

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

	snaps := New(db)

	// Take a snapshot.
	snap, err := snaps.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	// Drop the table.
	if _, err := db.Exec(`DROP TABLE test;`); err != nil {
		t.Fatal(err)
	}

	// Ensure the table is dropped
	if _, err := db.Exec(`SELECT * FROM test;`); err == nil {
		t.Fatal("expected error")
	}

	// Persist the snapshot to a buffer.
	buf := new(bytes.Buffer)
	sink := &testSnapshotSink{buf}
	if err := snap.Persist(sink); err != nil {
		t.Fatal(err)
	}

	// Restore the snapshot.
	if err := snaps.Restore(context.Background(), sink); err != nil {
		t.Fatal(err)
	}

	snap.Release()

	// Ensure the table is restored.
	rows, err := db.Query(`SELECT * FROM test;`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()

	var count int
	for rows.Next() {
		count++
	}
	if count != 3 {
		t.Fatalf("expected 3 rows, got %d", count)
	}
}

type testSnapshotSink struct {
	io.ReadWriter
}

func (t *testSnapshotSink) ID() string {
	return "test"
}

func (t *testSnapshotSink) Cancel() error {
	return nil
}

func (t *testSnapshotSink) Close() error {
	return nil
}
