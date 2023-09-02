//go:build !wasm

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

package nutsdb

import (
	"strings"
	"sync"

	"github.com/google/uuid"

	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/storage"
)

type subscriptionManager struct {
	subs map[string]nutsDBSubscription
	mu   sync.Mutex
}

func newSubscriptionManager() *subscriptionManager {
	return &subscriptionManager{
		subs: make(map[string]nutsDBSubscription),
	}
}

func (sm *subscriptionManager) Subscribe(ctx context.Context, prefix string, fn storage.SubscribeFunc) (context.CancelFunc, error) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	id, err := uuid.NewRandom()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(ctx)
	sub := nutsDBSubscription{
		ctx:    ctx,
		prefix: prefix,
		fn:     fn,
		cancel: cancel,
	}
	sm.subs[id.String()] = sub
	return cancel, nil
}

func (sm *subscriptionManager) Notify(ctx context.Context, key, value string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	log := context.LoggerFrom(ctx)
	log.Debug("Notifying subscriptions", "key", key)
	for id, sub := range sm.subs {
		select {
		case <-sub.ctx.Done():
			log.Debug("Subscription context done", "id", id, "prefix", sub.prefix)
			delete(sm.subs, id)
			continue
		default:
		}
		if sub.Matches(key) {
			log.Debug("Notifying subscription", "id", id, "prefix", sub.prefix)
			sub.Notify(key, value)
		} else {
			log.Debug("Skipping subscription", "id", id, "prefix", sub.prefix, "key", key)
		}
	}
}

func (sm *subscriptionManager) Close() {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	for id, sub := range sm.subs {
		sub.Close()
		delete(sm.subs, id)
	}
}

type nutsDBSubscription struct {
	ctx    context.Context
	prefix string
	fn     storage.SubscribeFunc
	cancel context.CancelFunc
}

func (sub *nutsDBSubscription) Context() context.Context {
	return sub.ctx
}

func (sub *nutsDBSubscription) Matches(key string) bool {
	return strings.HasPrefix(key, sub.prefix)
}

func (sub *nutsDBSubscription) Notify(key, value string) {
	sub.fn(key, value)
}

func (sub *nutsDBSubscription) Close() {
	sub.cancel()
}
