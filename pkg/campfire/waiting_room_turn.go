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

package campfire

import "github.com/webmeshproj/webmesh/pkg/context"

type turnWaitingRoom struct{}

func NewTURNWaitingRoom(ctx context.Context, opts Options) (WaitingRoom, error) {
	return &turnWaitingRoom{}, nil
}

// Connetions returns a channel that receives new incoming connections.
func (t *turnWaitingRoom) Connections() <-chan Stream {
	return nil
}

// Peers returns a channel that receives new peers that have joined the
// campfire. A new stream to the peer is opened for each peer and sent
// on the channel.
func (t *turnWaitingRoom) Peers() <-chan Stream {
	return nil
}

// Location returns the location of the campfire.
func (t *turnWaitingRoom) Location() *Location {
	return nil
}

// Errors returns a channel that receives errors.
func (t *turnWaitingRoom) Errors() <-chan error {
	return nil
}

// Close closes the waiting room.
func (t *turnWaitingRoom) Close() error {
	return nil
}
