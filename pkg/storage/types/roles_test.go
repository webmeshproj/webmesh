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

package types

import (
	"testing"

	v1 "github.com/webmeshproj/api/v1"
)

func TestRolesListEval(t *testing.T) {
	t.Parallel()

	tc := []struct {
		name    string
		roles   RolesList
		actions map[*v1.RBACAction]bool
	}{
		{
			name:  "nil roles list",
			roles: nil,
			actions: map[*v1.RBACAction]bool{
				{
					Resource: v1.RuleResource_RESOURCE_VOTES,
					Verb:     v1.RuleVerb_VERB_PUT,
				}: false,
			},
		},
		{
			name:  "empty roles list",
			roles: RolesList{},
			actions: map[*v1.RBACAction]bool{
				{
					Resource: v1.RuleResource_RESOURCE_VOTES,
					Verb:     v1.RuleVerb_VERB_PUT,
				}: false,
			},
		},
		{
			name: "allow all roles list",
			roles: RolesList{
				{
					Role: &v1.Role{
						Rules: []*v1.Rule{
							{
								Verbs:     []v1.RuleVerb{v1.RuleVerb_VERB_ALL},
								Resources: []v1.RuleResource{v1.RuleResource_RESOURCE_ALL},
							},
						},
					},
				},
			},
			actions: func() map[*v1.RBACAction]bool {
				a := map[*v1.RBACAction]bool{}
				for _, verb := range v1.RuleVerb_value {
					for _, resource := range v1.RuleResource_value {
						a[&v1.RBACAction{
							Resource: v1.RuleResource(resource),
							Verb:     v1.RuleVerb(verb),
						}] = true
					}
				}
				return a
			}(),
		},
		{
			name: "single action roles list",
			roles: RolesList{
				{
					Role: &v1.Role{
						Rules: []*v1.Rule{
							{
								Verbs:     []v1.RuleVerb{v1.RuleVerb_VERB_PUT},
								Resources: []v1.RuleResource{v1.RuleResource_RESOURCE_VOTES},
							},
						},
					},
				},
			},
			actions: func() map[*v1.RBACAction]bool {
				// Every action should be false except for the one allowed action
				a := map[*v1.RBACAction]bool{
					{
						Resource: v1.RuleResource_RESOURCE_VOTES,
						Verb:     v1.RuleVerb_VERB_PUT,
					}: true,
				}
				for _, verb := range v1.RuleVerb_value {
					if v1.RuleVerb(verb) == v1.RuleVerb_VERB_ALL {
						continue
					}
					for _, resource := range v1.RuleResource_value {
						if v1.RuleResource(resource) == v1.RuleResource_RESOURCE_ALL {
							continue
						}
						if v1.RuleResource(resource) == v1.RuleResource_RESOURCE_VOTES &&
							v1.RuleVerb(verb) == v1.RuleVerb_VERB_PUT {
							continue
						}
						a[&v1.RBACAction{
							Resource: v1.RuleResource(resource),
							Verb:     v1.RuleVerb(verb),
						}] = false
					}
				}
				return a
			}(),
		},
		{
			name: "single resource allow all roles list",
			roles: RolesList{
				{
					Role: &v1.Role{
						Rules: []*v1.Rule{
							{
								Verbs:     []v1.RuleVerb{v1.RuleVerb_VERB_ALL},
								Resources: []v1.RuleResource{v1.RuleResource_RESOURCE_ROLES},
							},
						},
					},
				},
			},
			actions: func() map[*v1.RBACAction]bool {
				// Every action for roles should be allowed
				a := map[*v1.RBACAction]bool{}
				for _, verb := range v1.RuleVerb_value {
					if v1.RuleVerb(verb) == v1.RuleVerb_VERB_ALL {
						continue
					}
					a[&v1.RBACAction{
						Resource: v1.RuleResource_RESOURCE_ROLES,
						Verb:     v1.RuleVerb(verb),
					}] = true
				}
				// All other actions should be false
				for _, verb := range v1.RuleVerb_value {
					if v1.RuleVerb(verb) == v1.RuleVerb_VERB_ALL {
						continue
					}
					for _, resource := range v1.RuleResource_value {
						if v1.RuleResource(resource) == v1.RuleResource_RESOURCE_ROLES {
							continue
						}
						a[&v1.RBACAction{
							Resource: v1.RuleResource(resource),
							Verb:     v1.RuleVerb(verb),
						}] = false
					}
				}
				return a
			}(),
		},
		{
			name: "single resource name allow all roles list",
			roles: RolesList{
				{
					Role: &v1.Role{
						Rules: []*v1.Rule{
							{
								Verbs:         []v1.RuleVerb{v1.RuleVerb_VERB_ALL},
								ResourceNames: []string{"foo"},
								Resources:     []v1.RuleResource{v1.RuleResource_RESOURCE_ROLES},
							},
						},
					},
				},
			},
			actions: func() map[*v1.RBACAction]bool {
				// Every action for roles named foo should be allowed
				a := map[*v1.RBACAction]bool{}
				for _, verb := range v1.RuleVerb_value {
					if v1.RuleVerb(verb) == v1.RuleVerb_VERB_ALL {
						continue
					}
					a[&v1.RBACAction{
						Resource:     v1.RuleResource_RESOURCE_ROLES,
						ResourceName: "foo",
						Verb:         v1.RuleVerb(verb),
					}] = true
				}
				// All other actions should be false
				for _, verb := range v1.RuleVerb_value {
					if v1.RuleVerb(verb) == v1.RuleVerb_VERB_ALL {
						continue
					}
					for _, resource := range v1.RuleResource_value {
						resourceName := "foo"
						if v1.RuleResource(resource) == v1.RuleResource_RESOURCE_ROLES {
							resourceName = "bar"
						}
						a[&v1.RBACAction{
							Resource:     v1.RuleResource(resource),
							ResourceName: resourceName,
							Verb:         v1.RuleVerb(verb),
						}] = false
					}
				}
				return a
			}(),
		},
	}

	for _, tt := range tc {
		t.Run(tt.name, func(t *testing.T) {
			for action, want := range tt.actions {
				if got := tt.roles.Eval(action); got != want {
					t.Errorf("RolesList.Eval(%+v) = %v, want %v", action, got, want)
				}
			}
		})
	}
}
