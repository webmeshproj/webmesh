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
	"context"
	"fmt"
	"math"
	"net/netip"

	v1 "github.com/webmeshproj/api/v1"

	"github.com/webmeshproj/webmesh/pkg/meshnet/netutil"
	"github.com/webmeshproj/webmesh/pkg/storage/errors"
	meshtypes "github.com/webmeshproj/webmesh/pkg/storage/types"
)

const (
	// DefaultMeshDomain is the default domain for the mesh network.
	DefaultMeshDomain = "webmesh.internal"
	// DefaultIPv4Network is the default IPv4 network for the mesh.
	DefaultIPv4Network = "172.16.0.0/12"
	// DefaultNetworkPolicy is the default network policy for the mesh.
	DefaultNetworkPolicy = "accept"
	// DefaultBootstrapListenAddress is the default listen address for the bootstrap transport.
	DefaultBootstrapListenAddress = "[::]:9001"
	// DefaultBootstrapAdvertiseAddress is the default advertise address for the bootstrap transport.
	DefaultBootstrapAdvertiseAddress = "127.0.0.1:9001"
	// DefaultBootstrapPort is the default port for the bootstrap transport.
	DefaultBootstrapPort = 9001
	// DefaultMeshAdmin is the default mesh admin node ID.
	DefaultMeshAdmin = "admin"
)

// BootstrapOptions are options for bootstrapping the database.
type BootstrapOptions struct {
	// MeshDomain is the mesh domain.
	MeshDomain string
	// IPv4Network is the IPv4 prefix.
	IPv4Network string
	// IPv6Network is the IPv6 prefix. If left unset,
	// one will be generated.
	IPv6Network string
	// Admin is the admin node ID.
	Admin string
	// DefaultNetworkPolicy is the default network policy.
	DefaultNetworkPolicy string
	// BootstrapNodes are the bootstrap nodes to use.
	BootstrapNodes []string
	// Voters are additional voting nodes to add to the voters group.
	Voters []string
	// DisableRBAC disables RBAC.
	DisableRBAC bool
}

func (b *BootstrapOptions) Default() {
	if b.IPv4Network == "" {
		b.IPv4Network = DefaultIPv4Network
	}
	if b.MeshDomain == "" {
		b.MeshDomain = DefaultMeshDomain
	}
	if b.Admin == "" {
		b.Admin = DefaultMeshAdmin
	}
	if b.DefaultNetworkPolicy == "" {
		b.DefaultNetworkPolicy = DefaultNetworkPolicy
	}
}

// BoostrapResults are the results of bootstrapping the database.
type BootstrapResults struct {
	// NetworkV4 is the IPv4 network.
	NetworkV4 netip.Prefix
	// NetworkV6 is the IPv6 network.
	NetworkV6 netip.Prefix
	// MeshDomain is the mesh domain.
	MeshDomain string
}

// Bootstrap attempts to bootstrap the given database. If data already exists,
// ErrAlreadyBootstrapped will be returned, but with results populated with the
// existing data.
func Bootstrap(ctx context.Context, db MeshDB, opts *BootstrapOptions) (results BootstrapResults, err error) {
	opts.Default()
	results.MeshDomain = opts.MeshDomain
	// Check if there is data already before we start.
	state, err := db.MeshState().GetMeshState(ctx)
	if err != nil && !errors.IsNotFound(err) {
		err = fmt.Errorf("get mesh domain: %w", err)
		return
	} else if err == nil {
		results.NetworkV4 = state.NetworkV4()
		results.NetworkV6 = state.NetworkV6()
		results.MeshDomain = state.Domain()
		return results, errors.ErrAlreadyBootstrapped
	}

	results.NetworkV4, err = netip.ParsePrefix(opts.IPv4Network)
	if err != nil {
		err = fmt.Errorf("parse IPv4 network: %w", err)
		return
	}
	if opts.IPv6Network != "" {
		results.NetworkV6, err = netip.ParsePrefix(opts.IPv6Network)
		if err != nil {
			err = fmt.Errorf("parse IPv6 network: %w", err)
			return
		}
		if results.NetworkV6.Bits() != netutil.DefaultULABits {
			err = fmt.Errorf("IPv6 network must be /%d", netutil.DefaultULABits)
			return
		}
	} else {
		results.NetworkV6, err = netutil.GenerateULA()
		if err != nil {
			err = fmt.Errorf("generate ULA: %w", err)
			return
		}
	}

	// Initialize the network state
	err = db.MeshState().SetMeshState(ctx, meshtypes.NetworkState{
		NetworkState: &v1.NetworkState{
			NetworkV4: results.NetworkV4.String(),
			NetworkV6: results.NetworkV6.String(),
			Domain:    opts.MeshDomain,
		},
	})
	if err != nil {
		err = fmt.Errorf("set network state to db: %w", err)
		return
	}

	// Initialize the RBAC system
	rb := db.RBAC()
	// Create an admin role and add the admin user/node to it.
	err = rb.PutRole(ctx, meshtypes.Role{Role: &v1.Role{
		Name: string(MeshAdminRole),
		Rules: []*v1.Rule{
			{
				Resources: []v1.RuleResource{v1.RuleResource_RESOURCE_ALL},
				Verbs:     []v1.RuleVerb{v1.RuleVerb_VERB_ALL},
			},
		},
	}})
	if err != nil {
		err = fmt.Errorf("create admin role: %w", err)
		return
	}
	err = rb.PutRoleBinding(ctx, meshtypes.RoleBinding{RoleBinding: &v1.RoleBinding{
		Name: string(MeshAdminRole),
		Role: string(MeshAdminRoleBinding),
		Subjects: []*v1.Subject{
			{
				Name: opts.Admin,
				Type: v1.SubjectType_SUBJECT_NODE,
			},
			{
				Name: opts.Admin,
				Type: v1.SubjectType_SUBJECT_USER,
			},
		},
	}})
	if err != nil {
		err = fmt.Errorf("create admin role binding: %w", err)
		return
	}
	// Create a "voters" role and group then add all the bootstrap servers to it.
	err = rb.PutRole(ctx, meshtypes.Role{Role: &v1.Role{
		Name: string(VotersRole),
		Rules: []*v1.Rule{
			{
				Resources: []v1.RuleResource{v1.RuleResource_RESOURCE_VOTES},
				Verbs:     []v1.RuleVerb{v1.RuleVerb_VERB_PUT},
			},
		},
	}})
	if err != nil {
		err = fmt.Errorf("create voters role: %w", err)
		return
	}
	err = rb.PutGroup(ctx, meshtypes.Group{Group: &v1.Group{
		Name: string(VotersGroup),
		Subjects: func() []*v1.Subject {
			out := make([]*v1.Subject, 0)
			out = append(out, &v1.Subject{
				Type: v1.SubjectType_SUBJECT_NODE,
				Name: opts.Admin,
			})
			for _, id := range opts.BootstrapNodes {
				out = append(out, &v1.Subject{
					Type: v1.SubjectType_SUBJECT_NODE,
					Name: string(id),
				})
			}
			if opts.Voters != nil {
				for _, voter := range opts.Voters {
					out = append(out, &v1.Subject{
						Type: v1.SubjectType_SUBJECT_NODE,
						Name: voter,
					})
				}
			}
			return out
		}(),
	}})
	if err != nil {
		err = fmt.Errorf("create voters group: %w", err)
		return
	}
	err = rb.PutRoleBinding(ctx, meshtypes.RoleBinding{RoleBinding: &v1.RoleBinding{
		Name: string(BootstrapVotersRoleBinding),
		Role: string(VotersRole),
		Subjects: []*v1.Subject{
			{
				Type: v1.SubjectType_SUBJECT_GROUP,
				Name: string(VotersGroup),
			},
		},
	}})
	if err != nil {
		err = fmt.Errorf("create voters role binding: %w", err)
		return
	}
	// We initialized rbac, but if the caller wants, we'll go ahead and disable it.
	if opts.DisableRBAC {
		err = rb.SetEnabled(ctx, false)
		if err != nil {
			err = fmt.Errorf("disable rbac: %w", err)
			return
		}
	}

	// Initialize the Networking system.
	nw := db.Networking()

	// Create a network ACL that ensures bootstrap servers and admins can continue to
	// communicate with each other.
	// TODO: This should be filtered to only apply to internal traffic.
	err = nw.PutNetworkACL(ctx, meshtypes.NetworkACL{NetworkACL: &v1.NetworkACL{
		Name:             string(BootstrapNodesNetworkACLName),
		Priority:         math.MaxInt32,
		SourceNodes:      []string{"group:" + string(VotersGroup)},
		DestinationNodes: []string{"group:" + string(VotersGroup)},
		Action:           v1.ACLAction_ACTION_ACCEPT,
	}})
	if err != nil {
		err = fmt.Errorf("create bootstrap nodes network acl: %w", err)
		return
	}
	// Apply a default accept policy if configured
	if opts.DefaultNetworkPolicy == "accept" {
		err = nw.PutNetworkACL(ctx, meshtypes.NetworkACL{NetworkACL: &v1.NetworkACL{
			Name:             "default-accept",
			Priority:         math.MinInt32,
			SourceNodes:      []string{"*"},
			DestinationNodes: []string{"*"},
			SourceCIDRs:      []string{"*"},
			DestinationCIDRs: []string{"*"},
			Action:           v1.ACLAction_ACTION_ACCEPT,
		}})
		if err != nil {
			err = fmt.Errorf("create default accept network ACL: %w", err)
			return
		}
	}
	// We're done!
	return results, nil
}
