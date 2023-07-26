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

package admin

import (
	"testing"

	v1 "github.com/webmeshproj/api/v1"

	"github.com/webmeshproj/node/pkg/context"
)

func TestListNetworkACLs(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	server := newTestServer(t)

	// No empty condition due to system acls created during bootstrap

	// Place a network acl
	_, err := server.PutNetworkACL(ctx, &v1.NetworkACL{
		Name:             "test-acl",
		SourceNodes:      []string{"foo"},
		DestinationCidrs: []string{"0.0.0.0/0"},
	})
	if err != nil {
		t.Errorf("PutNetworkACL() error = %v", err)
		return
	}
	var acl *v1.NetworkACL
	acls, err := server.ListNetworkACLs(ctx, nil)
	if err != nil {
		t.Errorf("ListNetworkACLs() error = %v", err)
		return
	}
	for _, a := range acls.GetItems() {
		if a.GetName() == "test-acl" {
			acl = a
			break
		}
	}
	if acl == nil {
		t.Errorf("ListNetworkACLs() did not return the expected ACL")
	}
	if len(acl.GetSourceNodes()) != 1 {
		t.Errorf("ListNetworkACLs() returned an ACL with unexpected source nodes")
	} else if acl.GetSourceNodes()[0] != "foo" {
		t.Errorf("ListNetworkACLs() returned an ACL with unexpected source nodes")
	}
	if len(acl.GetDestinationCidrs()) != 1 {
		t.Errorf("ListNetworkACLs() returned an ACL with unexpected destination cidrs")
	} else if acl.GetDestinationCidrs()[0] != "0.0.0.0/0" {
		t.Errorf("ListNetworkACLs() returned an ACL with unexpected destination cidrs")
	}
}
