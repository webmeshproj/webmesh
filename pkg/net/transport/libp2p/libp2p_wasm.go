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

package libp2p

import (
	"errors"
	"io"

	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/net/transport"
)

type DHTAnnounceOptions struct {
}

func NewDHTAnnouncer(ctx context.Context, opts DHTAnnounceOptions, join transport.JoinServer) (io.Closer, error) {
	return nil, errors.New("not implemented")
}

type DHTJoinOptions struct {
}

func NewDHTJoinRoundTripper(opts DHTJoinOptions) transport.JoinRoundTripper {
	return nil, errors.New("not implemented")
}
