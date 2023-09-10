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

package util

import (
	"fmt"
	"math"
)

// Pointer returns a pointer to the given value.
func Pointer[T any](t T) *T {
	return &t
}

// Contains returns true if the given slice contains the given item.
func Contains[T comparable](sl []T, item T) bool {
	for _, v := range sl {
		if v == item {
			return true
		}
	}
	return false
}

// UpsertSlice with insert the given item into a slice if it does not exist,
// otherwise it will update the existing item and return the updated slice.
func UpsertSlice[T comparable](sl []T, item T) []T {
	for i, v := range sl {
		if v == item {
			sl[i] = item
			return sl
		}
	}
	return append(sl, item)
}

// PrettyByteSize returns a human-readable string of the given byte size.
func PrettyByteSize(b int64) string {
	bf := float64(b)
	for _, unit := range []string{"", "Ki", "Mi", "Gi", "Ti", "Pi", "Ei", "Zi"} {
		if math.Abs(bf) < 1024.0 {
			return fmt.Sprintf("%3.1f%sB", bf, unit)
		}
		bf /= 1024.0
	}
	return fmt.Sprintf("%.1fYiB", bf)
}

// AllUnique returns true if all elements in the given slice are unique.
func AllUnique[T comparable](sl []T) bool {
	seen := make(map[T]bool)
	for _, v := range sl {
		if seen[v] {
			return false
		}
		seen[v] = true
	}
	return true
}
