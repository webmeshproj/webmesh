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

package networking

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"

	v1 "github.com/webmeshproj/api/v1"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/webmeshproj/webmesh/pkg/storage/storageutil"
)

// ValidateRoute validates a Route.
func ValidateRoute(route *v1.Route) error {
	if route.GetName() == "" {
		return errors.New("route name is required")
	}
	if route.GetNode() == "" {
		return errors.New("route node is required")
	}
	if len(route.GetDestinationCidrs()) == 0 {
		return errors.New("route destination CIDRs are required")
	}
	if !storageutil.IsValidID(route.GetName()) {
		return errors.New("route name must be a valid ID")
	}
	if !storageutil.IsValidID(route.GetNode()) {
		return errors.New("route node must be a valid ID")
	}
	if route.GetNextHopNode() != "" {
		if !storageutil.IsValidID(route.GetNextHopNode()) {
			return errors.New("route next hop node must be a valid ID")
		}
	}
	for _, cidr := range route.GetDestinationCidrs() {
		if _, err := netip.ParsePrefix(cidr); err != nil {
			return fmt.Errorf("parse prefix %q: %w", cidr, err)
		}
	}
	return nil
}

// Routes is a list of routes.
type Routes []Route

// Len returns the length of the Routes list.
func (a Routes) Len() int { return len(a) }

// Swap swaps the routes at indexes i and j.
func (a Routes) Swap(i, j int) { a[i], a[j] = a[j], a[i] }

// Less returns whether the name of the route at index i is less than the name of the route at index j.
func (a Routes) Less(i, j int) bool {
	return a[i].Name < a[j].Name
}

// Sort sorts the routes by name.
func (a Routes) Sort() {
	sort.Sort(a)
}

// Proto returns the protobuf representation of the Routes.
func (a Routes) Proto() []*v1.Route {
	if a == nil {
		return nil
	}
	proto := make([]*v1.Route, len(a))
	for i, rt := range a {
		proto[i] = rt.Proto()
	}
	return proto
}

// Route wraps a Route.
type Route struct {
	*v1.Route
}

// Proto returns the protobuf representation of the route.
func (r *Route) Proto() *v1.Route {
	return r.Route
}

// Marshal marshals the route to protobuf json.
func (r Route) MarshalJSON() ([]byte, error) {
	return protojson.Marshal(r.Route)
}

// Unmarshal unmarshals the route from a protobuf.
func (r *Route) UnmarshalJSON(data []byte) error {
	var rt v1.Route
	err := protojson.Unmarshal(data, &rt)
	if err != nil {
		return fmt.Errorf("unmarshal route: %w", err)
	}
	r.Route = &rt
	return nil
}

// Equals returns whether the routes are equal.
func (r *Route) Equals(other *Route) bool {
	if r.GetName() != other.GetName() {
		return false
	}
	if r.GetNode() != other.GetNode() {
		return false
	}
	if r.GetNextHopNode() != other.GetNextHopNode() {
		return false
	}
	if len(r.GetDestinationCidrs()) != len(other.GetDestinationCidrs()) {
		return false
	}
	for i, cidr := range r.GetDestinationCidrs() {
		if cidr != other.GetDestinationCidrs()[i] {
			return false
		}
	}
	return true
}

// DestinationPrefixes returns the destination prefixes for the route.
func (r *Route) DestinationPrefixes() []netip.Prefix {
	return toPrefixes(r.GetDestinationCidrs())
}
