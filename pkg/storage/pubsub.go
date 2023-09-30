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

	"github.com/webmeshproj/webmesh/pkg/storage/types"
)

// Topic represents a topic for a pubsub subscription. Generic
// implementations can be made so long as they can be JSON encoded.
type Topic[T any] string

const (
	// TopicAll is the topic for all changes.
	TopicAll Topic[any] = ""
	// TopicPeers is the topic for peer changes.
	TopicPeers Topic[types.MeshNode] = "peers"
	// TopicEdges is the topic for edge changes.
	TopicEdges Topic[types.MeshEdge] = "edges"
)

// SubscribeFunc is a function that subscribes to a topic.
type SubscribeFunc[T any] func(T)

// PubSub is the interface for the pubsub system.
type PubSub[T any] interface {
	// Publish publishes a message to the given topic.
	Publish(Topic[T], T) error
	// Subscribe subscribes to the given topic.
	Subscribe(context.Context, Topic[T], SubscribeFunc[T]) (context.CancelFunc, error)
}
