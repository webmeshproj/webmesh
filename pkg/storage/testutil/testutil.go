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

// Package testutil contains testing utilities for storage providers and backends.
package testutil

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/webmeshproj/webmesh/pkg/storage"
)

// DropStorage is a storage interface that can be dropped entirely.
// This is primarily used for testing.
type DropStorage interface {
	// DropAll drops all data from the storage. This is primarily used
	// for testing.
	DropAll(ctx context.Context) error
}

// NewProviderFunc is a function that returns a new started storage provider.
// It should have unique identifying properties for each call and not be
// bootstrapped. The providers listen port must be available on localhost.
type NewProviderFunc func(ctx context.Context, t *testing.T) storage.Provider

// MustBootstrap is a helper function that calls Bootstrap and fails the test if there
// is an error.
func MustBootstrap(ctx context.Context, t *testing.T, provider storage.Provider) {
	t.Helper()
	err := provider.Bootstrap(ctx)
	if err != nil {
		t.Fatalf("Failed to bootstrap provider: %v", err)
	}
}

// MustAddVoter is a helper function that adds a voter to the consensus group and fails
// the test if there is an error.
func MustAddVoter(ctx context.Context, t *testing.T, leader, voter storage.Provider) {
	t.Helper()
	voterInfo := voter.Status().GetPeers()
	if len(voterInfo) != 1 {
		t.Fatalf("Expected voter to have one peer in voter, got %d", len(voterInfo))
	}
	err := leader.Consensus().AddVoter(ctx, voterInfo[0])
	if err != nil {
		t.Fatalf("Failed to add voter: %v", err)
	}
}

// MustAddObserver is a helper function that adds an observer to the consensus group and fails
// the test if there is an error.
func MustAddObserver(ctx context.Context, t *testing.T, leader, observer storage.Provider) {
	t.Helper()
	obsInfo := observer.Status().GetPeers()
	if len(obsInfo) != 1 {
		t.Fatalf("Expected observer to have one peer in voter, got %d", len(obsInfo))
	}
	err := leader.Consensus().AddObserver(ctx, obsInfo[0])
	if err != nil {
		t.Fatalf("Failed to add observer: %v", err)
	}
}

// Eventually is a function that should eventually meet the given condition.
type Eventually[T comparable] func() T

// Condition is a function that returns true if the condition is met.
type Condition[T comparable] func(T) bool

// ShouldNotError eventually should not error.
func (e Eventually[T]) ShouldNotError(after time.Duration, tick time.Duration) bool {
	return e.Should(after, tick, func(err T) bool {
		er, ok := any(err).(error)
		if !ok {
			// Nil errors are not errors. This is a special case.
			return true
		}
		return er == nil
	})
}

// ShouldError eventually should error.
func (e Eventually[T]) ShouldError(after time.Duration, tick time.Duration) bool {
	return e.Should(after, tick, func(err T) bool {
		er, ok := any(err).(error)
		if !ok {
			return false
		}
		return er == nil
	})
}

// ShouldErrorWith eventually should error with the given error.
func (e Eventually[T]) ShouldErrorWith(after time.Duration, tick time.Duration, expected error) bool {
	return e.Should(after, tick, func(err T) bool {
		er, ok := any(err).(error)
		if !ok {
			return false
		}
		return errors.Is(er, expected)
	})
}

// ShouldEqual eventually should equal the given value.
func (e Eventually[T]) ShouldEqual(after time.Duration, tick time.Duration, expected T) bool {
	return e.Should(after, tick, func(val T) bool {
		return val == expected
	})
}

// ShouldNotEqual eventually should not equal the given value.
func (e Eventually[T]) ShouldNotEqual(after time.Duration, tick time.Duration, expected T) bool {
	return e.Should(after, tick, func(val T) bool {
		return val != expected
	})
}

// Should eventually meet the given condition.
func (e Eventually[T]) Should(after time.Duration, tick time.Duration, condition func(T) bool) bool {
	// Try the condition once immediately
	res := e()
	if condition(res) {
		return true
	}
	done := time.After(after)
	ticker := time.NewTicker(tick)
	defer ticker.Stop()
	for {
		select {
		case <-done:
			return false
		case <-ticker.C:
			res := e()
			if condition(res) {
				return true
			}
		}
	}
}
