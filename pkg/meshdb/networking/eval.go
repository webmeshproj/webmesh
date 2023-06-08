/*
Copyright 2023.

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

// Package networking contains interfaces to the database models for Network ACLs and Routes.
package networking

import (
	"sort"

	v1 "github.com/webmeshproj/api/v1"
)

// ACLs is a list of Network ACLs. It contains methods for evaluating actions against
// contained permissions. It also allows for sorting by priority.
type ACLs []*v1.NetworkACL

func (a ACLs) Len() int { return len(a) }

func (a ACLs) Swap(i, j int) { a[i], a[j] = a[j], a[i] }

func (a ACLs) Less(i, j int) bool {
	return a[i].GetPriority() < a[j].GetPriority()
}

// SortDirection is the direction to sort ACLs.
type SortDirection int

const (
	// SortDescending sorts ACLs in descending order.
	SortDescending SortDirection = iota
	// SortAscending sorts ACLs in ascending order.
	SortAscending
)

// Sort sorts the ACLs by priority.
func (a ACLs) Sort(direction SortDirection) {
	switch direction {
	case SortAscending:
		sort.Sort(a)
	case SortDescending:
		sort.Sort(sort.Reverse(a))
	default:
		sort.Sort(sort.Reverse(a))
	}
}
