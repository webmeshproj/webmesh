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

package storage

import (
	"bytes"
	"fmt"
	"io"

	"github.com/dgraph-io/badger/v4"
)

type badgerStorage struct {
	db       *badger.DB
	readonly bool
}

func newBadgerStorage(opts *Options) (Storage, error) {
	var badgeropts badger.Options
	if opts.InMemory {
		badgeropts = badger.DefaultOptions("").WithInMemory(true)
	} else {
		badgeropts = badger.DefaultOptions(opts.DiskPath)
	}
	db, err := badger.Open(badgeropts)
	if err != nil {
		return nil, fmt.Errorf("badger open: %w", err)
	}
	return &badgerStorage{db: db}, nil
}

// Get returns the value of a key.
func (b *badgerStorage) Get(key string) (string, error) {
	var value string
	err := b.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get([]byte(key))
		if err != nil {
			return fmt.Errorf("badger get: %w", err)
		}
		err = item.Value(func(val []byte) error {
			value = string(val)
			return nil
		})
		if err != nil {
			return fmt.Errorf("badger get: %w", err)
		}
		return nil
	})
	return value, err
}

// Put sets the value of a key.
func (b *badgerStorage) Put(key, value string) error {
	if b.readonly {
		return ErrReadOnly
	}
	err := b.db.Update(func(txn *badger.Txn) error {
		err := txn.Set([]byte(key), []byte(value))
		if err != nil {
			return fmt.Errorf("badger put: %w", err)
		}
		return nil
	})
	return err
}

// Delete removes a key.
func (b *badgerStorage) Delete(key string) error {
	if b.readonly {
		return ErrReadOnly
	}
	err := b.db.Update(func(txn *badger.Txn) error {
		err := txn.Delete([]byte(key))
		if err != nil {
			return fmt.Errorf("badger delete: %w", err)
		}
		return nil
	})
	return err
}

// List returns all keys with a given prefix.
func (b *badgerStorage) List(prefix string) ([]string, error) {
	var keys []string
	err := b.db.View(func(txn *badger.Txn) error {
		it := txn.NewIterator(badger.DefaultIteratorOptions)
		defer it.Close()
		for it.Seek([]byte(prefix)); it.ValidForPrefix([]byte(prefix)); it.Next() {
			item := it.Item()
			k := item.Key()
			keys = append(keys, string(k))
		}
		return nil
	})
	return keys, err
}

// Snapshot returns a snapshot of the storage.
func (b *badgerStorage) Snapshot() (io.ReadCloser, error) {
	err := b.db.RunValueLogGC(0.5)
	if err != nil {
		return nil, fmt.Errorf("badger snapshot: %w", err)
	}
	var buf bytes.Buffer
	_, err = b.db.Backup(&buf, 0)
	if err != nil {
		return nil, fmt.Errorf("badger snapshot: %w", err)
	}
	return io.NopCloser(&buf), nil
}

// Restore restores a snapshot of the storage.
func (b *badgerStorage) Restore(r io.Reader) error {
	if b.readonly {
		return ErrReadOnly
	}
	err := b.db.DropAll()
	if err != nil {
		return fmt.Errorf("badger restore: %w", err)
	}
	err = b.db.Load(r, 16)
	if err != nil {
		return fmt.Errorf("badger restore: %w", err)
	}
	return nil
}

func (b *badgerStorage) ReadOnly() Storage {
	if b.readonly {
		return b
	}
	return &badgerStorage{db: b.db, readonly: true}
}

// Close closes the storage.
func (b *badgerStorage) Close() error {
	// Don't close the database if it's a read-only view.
	if b.readonly {
		return nil
	}
	return b.db.Close()
}
