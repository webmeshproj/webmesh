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

// Package idauth is an authentication plugin based on libp2p peer IDs.
// The public key is extracted from the ID and the authentication payload
// is a signature of the ID corresponding to the private key.
package idauth

import (
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/mitchellh/mapstructure"
	"github.com/spf13/pflag"
	v1 "github.com/webmeshproj/api/go/v1"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/crypto"
	"github.com/webmeshproj/webmesh/pkg/version"
)

const (
	// DefaultTimeSkew is the default time skew.
	DefaultTimeSkew = 1
	// DefaultRemoteFetchRetryInterval is the default remote fetch retry interval.
	DefaultRemoteFetchRetryInterval = 3 * time.Second
	// DefaultRemoteFetchRetries is the default number of remote fetch retries.
	DefaultRemoteFetchRetries = 5
	// DefaultWatchInterval is the default watch interval.
	DefaultWatchInterval = time.Minute
	// InlineSource is the source key for inline IDs.
	InlineSource = "inline"
)

// Plugin is the ID auth plugin.
type Plugin struct {
	v1.UnimplementedPluginServer
	v1.UnimplementedAuthPluginServer

	config     Config
	allowedIDs AllowedIDs
	closec     chan struct{}
	mu         sync.RWMutex
}

// NewWithConfig returns a preconfigured plugin. Close should
// be called on the plugin when it is no longer needed.
func NewWithConfig(ctx context.Context, config Config) (*Plugin, error) {
	var p Plugin
	ms := config.AsMapStructure()
	spb, err := structpb.NewStruct(ms)
	if err != nil {
		return nil, fmt.Errorf("failed to convert config to struct: %w", err)
	}
	_, err = p.Configure(ctx, &v1.PluginConfiguration{Config: spb})
	if err != nil {
		return nil, fmt.Errorf("failed to configure plugin: %w", err)
	}
	return &p, nil
}

// AllowedIDs is a map of source files to a set of the allowed IDs in that file.
type AllowedIDs map[string]map[string]struct{}

// HasID returns true if the given ID is in the allowed IDs.
func (a AllowedIDs) HasID(id string) bool {
	for _, ids := range a {
		if _, ok := ids[id]; ok {
			return true
		}
	}
	return false
}

// Config is the configuration for the ID auth plugin.
type Config struct {
	// TimeSkew is the maximum allowed time skew between the client and server
	// as a multiple of 30 seconds. Defaults to 1.
	TimeSkew int `mapstructure:"time-skew,omitempty" koanf:"time-skew,omitempty"`
	// AllowedIDs is a list of allowed peer IDs.
	AllowedIDs []string `mapstructure:"allowed-ids,omitempty" koanf:"allowed-ids,omitempty"`
	// IDFiles are paths to files containing lists of allowed peer IDs.
	// These can be local files or files in a remote HTTP(S) location.
	IDFiles []string `mapstructure:"id-files,omitempty" koanf:"id-files,omitempty"`
	// WatchIDFiles indicates that the ID files should be watched for changes.
	WatchIDFiles bool `mapstructure:"watch-id-files,omitempty" koanf:"watch-id-files,omitempty"`
	// WatchInterval is the interval to poll for changes to remote ID files. Local files
	// use the filesystem's native change notification mechanism.
	WatchInterval time.Duration `mapstructure:"watch-interval,omitempty" koanf:"watch-interval,omitempty"`
	// RemoteFetchRetries is the number of times to retry fetching a remote ID file.
	RemoteFetchRetries int `mapstructure:"remote-fetch-retries,omitempty" koanf:"remote-fetch-retries,omitempty"`
	// RemoteFetchRetryInterval is the interval to wait between retries to fetch a remote ID file.
	RemoteFetchRetryInterval time.Duration `mapstructure:"remote-fetch-retry-interval,omitempty" koanf:"remote-fetch-retry-interval,omitempty"`
	// InsecureAllowAll allows all peer IDs. This is insecure and should only be used for testing.
	InsecureAllowAll bool `mapstructure:"insecure-allow-all,omitempty" koanf:"insecure-allow-all,omitempty"`
}

// NewDefaultConfig returns a new default config.
func NewDefaultConfig() Config {
	var c Config
	return c.Default()
}

// BindFlags binds the config flags to the given flag set.
func (c *Config) BindFlags(prefix string, fs *pflag.FlagSet) {
	fs.IntVar(&c.TimeSkew, prefix+"time-skew", c.TimeSkew, "Maximum allowed time skew between the client and server as a multiple of 30 seconds. 0 defaults to 30 seconds. Set to -1 to disable time skew checking.")
	fs.StringSliceVar(&c.AllowedIDs, prefix+"allowed-ids", c.AllowedIDs, "List of allowed peer IDs")
	fs.StringSliceVar(&c.IDFiles, prefix+"id-files", c.IDFiles, "Path to a file containing a list of allowed peer IDs")
	fs.BoolVar(&c.WatchIDFiles, prefix+"watch-id-files", c.WatchIDFiles, "Watch ID files for changes")
	fs.DurationVar(&c.WatchInterval, prefix+"watch-interval", c.WatchInterval, "Interval to poll for changes to remote ID files. When unset or less than zero, defaults to 1 minute.")
	fs.IntVar(&c.RemoteFetchRetries, prefix+"remote-fetch-retries", c.RemoteFetchRetries, "Number of times to retry fetching a remote ID file. Defaults to 5. Set to -1 to disable retries.")
	fs.DurationVar(&c.RemoteFetchRetryInterval, prefix+"remote-fetch-retry-interval", c.RemoteFetchRetryInterval, "Interval to wait between retries to fetch a remote ID file. Defaults to 3 seconds.")
	fs.BoolVar(&c.InsecureAllowAll, prefix+"insecure-allow-all", c.InsecureAllowAll, "Allow all peer IDs. This is insecure and should only be used for testing.")
}

// Default sets the default values for the config.
func (c *Config) Default() Config {
	if c == nil {
		c = &Config{}
	}
	if c.TimeSkew == 0 {
		c.TimeSkew = DefaultTimeSkew
	}
	if c.RemoteFetchRetryInterval == 0 {
		c.RemoteFetchRetryInterval = DefaultRemoteFetchRetryInterval
	}
	if c.RemoteFetchRetries == 0 {
		c.RemoteFetchRetries = DefaultRemoteFetchRetries
	}
	if c.WatchInterval <= 0 {
		c.WatchInterval = DefaultWatchInterval
	}
	return *c
}

// Now returns the current time.
var Now = time.Now

// CurrentSigData returns the current expected signature data
// based on the configured time skew.
func (c *Config) CurrentSigData(id string) [][]byte {
	var data [][]byte
	t := Now().Truncate(time.Second * 30).Unix()
	data = append(data, []byte(fmt.Sprintf("%s:%d", id, t)))
	if c.TimeSkew <= 0 {
		return data
	}
	for i := 1; i <= c.TimeSkew; i++ {
		t1 := Now().Truncate(time.Second*30).Unix() - int64(i*30)
		t2 := Now().Truncate(time.Second*30).Unix() + int64(i*30)
		data = append(data, []byte(fmt.Sprintf("%s:%d", id, t1)), []byte(fmt.Sprintf("%s:%d", id, t2)))
	}
	return data
}

func (c *Config) AsMapStructure() map[string]any {
	return map[string]any{
		"time-skew":                   c.TimeSkew,
		"allowed-ids":                 toAnySlice(c.AllowedIDs),
		"id-files":                    toAnySlice(c.IDFiles),
		"watch-id-files":              c.WatchIDFiles,
		"watch-interval":              int(c.WatchInterval),
		"remote-fetch-retries":        c.RemoteFetchRetries,
		"remote-fetch-retry-interval": int(c.RemoteFetchRetryInterval),
		"insecure-allow-all":          c.InsecureAllowAll,
	}
}

func toAnySlice(in []string) []any {
	out := make([]any, len(in))
	for i, v := range in {
		out[i] = any(v)
	}
	return out
}

func (c *Config) SetMapStructure(in map[string]any) {
	_ = mapstructure.Decode(in, c)
}

const (
	peerIDHeader    = "x-webmesh-id-auth-peer-id"
	signatureHeader = "x-webmesh-id-auth-signature"
)

func (p *Plugin) GetInfo(context.Context, *emptypb.Empty) (*v1.PluginInfo, error) {
	return &v1.PluginInfo{
		Name:        "id-auth",
		Version:     version.Version,
		Description: "ID authentication plugin",
		Capabilities: []v1.PluginInfo_PluginCapability{
			v1.PluginInfo_AUTH,
		},
	}, nil
}

func (p *Plugin) Configure(ctx context.Context, req *v1.PluginConfiguration) (*emptypb.Empty, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closec != nil {
		close(p.closec)
	}
	p.closec = make(chan struct{})
	var config Config
	err := mapstructure.Decode(req.Config.AsMap(), &config)
	if err != nil {
		return nil, err
	}
	p.config = config.Default()
	allowedIDs := make(AllowedIDs)
	allowedIDs[InlineSource] = make(map[string]struct{})
	for _, id := range p.config.AllowedIDs {
		allowedIDs[InlineSource][id] = struct{}{}
	}
	if len(p.config.IDFiles) > 0 {
		for _, src := range p.config.IDFiles {
			allowedIDs[src] = make(map[string]struct{})
			var idData []byte
			switch {
			case strings.HasPrefix(src, "http://"), strings.HasPrefix(src, "https://"):
				idData, err = getWithRetry(ctx, src, p.config.RemoteFetchRetries, p.config.RemoteFetchRetryInterval)
				if err != nil {
					return nil, fmt.Errorf("failed to read ID file: %w", err)
				}
				if p.config.WatchIDFiles {
					go p.watchRemoteFile(ctx, src)
				}
			default:
				path := strings.TrimPrefix(src, "file://")
				idData, err = os.ReadFile(path)
				if err != nil {
					return nil, fmt.Errorf("failed to read ID file: %w", err)
				}
				if p.config.WatchIDFiles {
					go p.watchLocalFile(ctx, path)
				}
			}
			ids := strings.Split(string(idData), "\n")
			for _, id := range ids {
				id = strings.TrimSpace(id)
				if id == "" {
					continue
				}
				allowedIDs[src][id] = struct{}{}
			}
		}
	}
	var haveIDs bool
	for ms := range allowedIDs {
		if len(allowedIDs[ms]) > 0 {
			haveIDs = true
			break
		}
	}
	if !haveIDs {
		return nil, fmt.Errorf("no allowed IDs configured")
	}
	p.allowedIDs = allowedIDs
	return &emptypb.Empty{}, nil
}

func (p *Plugin) Authenticate(ctx context.Context, req *v1.AuthenticationRequest) (*v1.AuthenticationResponse, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	log := context.LoggerFrom(ctx).With("component", "id-auth")
	// We should be able to extract a public key from the ID and verify that the ID
	// was signed by the private key for it.
	id, ok := req.GetHeaders()[peerIDHeader]
	if !ok {
		return nil, fmt.Errorf("missing %s header", peerIDHeader)
	}
	// Fast path, make sure it's in the list of allowed IDs.
	if !p.config.InsecureAllowAll && !p.allowedIDs.HasID(id) {
		log.Warn("Peer ID is not in the allow list", "id", id)
		return nil, fmt.Errorf("peer ID %s is not in the allow list", id)
	}
	encodedSig, ok := req.GetHeaders()[signatureHeader]
	if !ok {
		return nil, fmt.Errorf("missing %s header", signatureHeader)
	}
	sig, err := base64.StdEncoding.DecodeString(encodedSig)
	if err != nil {
		return nil, fmt.Errorf("failed to decode signature: %w", err)
	}
	pubKey, err := crypto.PubKeyFromID(id)
	if err != nil {
		return nil, fmt.Errorf("failed to extract public key from ID: %w", err)
	}
	var valid bool
	for _, data := range p.config.CurrentSigData(id) {
		valid, err = pubKey.AsIdentity().Verify(data, sig)
		if err != nil {
			log.Debug("Failed to verify signature", "error", err.Error())
			continue
		}
		if valid {
			break
		}
	}
	if err != nil {
		return nil, fmt.Errorf("failed to verify signature: %w", err)
	}
	if !valid {
		return nil, fmt.Errorf("no valid signature found in %d attempts", len(p.config.CurrentSigData(id)))
	}
	return &v1.AuthenticationResponse{
		Id: id,
	}, nil
}

func (p *Plugin) Close(ctx context.Context, req *emptypb.Empty) (*emptypb.Empty, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closec != nil {
		close(p.closec)
	}
	return &emptypb.Empty{}, nil
}

func (p *Plugin) watchLocalFile(ctx context.Context, fpath string) {
	log := context.LoggerFrom(ctx).With("component", "id-auth").With("watched-file", fpath)
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Error("Failed to create file watcher", "error", err.Error())
		return
	}
	defer watcher.Close()
	filename := filepath.Base(fpath)
	watchDir := filepath.Dir(fpath)
	matchEvent := func(event fsnotify.Event) bool {
		eventBase := filepath.Base(event.Name)
		return (event.Has(fsnotify.Write) || event.Has(fsnotify.Create) || event.Has(fsnotify.Remove)) &&
			eventBase == filename
	}
	go func() {
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				evlog := log.With("event", event.String())
				if !matchEvent(event) {
					evlog.Debug("Ignoring event")
					continue
				}
				p.mu.Lock()
				newIDs := make(map[string]struct{})
				if !event.Has(fsnotify.Remove) {
					evlog.Debug("ID file updated, reloading")
					data, err := os.ReadFile(fpath)
					if err != nil {
						log.Error("Failed to read ID file", "error", err.Error())
						p.mu.Unlock()
						continue
					}
					ids := strings.Split(string(data), "\n")
				IDs:
					for _, id := range ids {
						id = strings.TrimSpace(id)
						if id == "" {
							continue IDs
						}
						newIDs[id] = struct{}{}
					}
				} else {
					evlog.Debug("ID file removed, removing from allowed IDs")
				}
				p.allowedIDs[fpath] = newIDs
				p.mu.Unlock()
			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				log.Error("File watcher error", "error", err.Error())
			}
		}
	}()
	log.Info("Watching directory for changes to file", "directory", watchDir, "file", filename)
	err = watcher.Add(watchDir + string(os.PathSeparator))
	if err != nil {
		log.Error("Failed to watch file", "file", fpath, "error", err.Error())
		return
	}
	<-p.closec
}

func (p *Plugin) watchRemoteFile(ctx context.Context, url string) {
	log := context.LoggerFrom(ctx).With("component", "id-auth")
	t := time.NewTicker(p.config.WatchInterval)
	defer t.Stop()
	for {
		select {
		case <-p.closec:
			return
		case <-t.C:
			p.mu.Lock()
			log.Debug("Fetching remote ID list", "url", url)
			ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
			data, err := getWithRetry(ctx, url, p.config.RemoteFetchRetries, p.config.RemoteFetchRetryInterval)
			cancel()
			if err != nil {
				log.Warn("Failed to fetch remote ID list", "url", url, "error", err.Error())
				p.mu.Unlock()
				continue
			}
			ids := strings.Split(string(data), "\n")
			seen := make(map[string]struct{})
			for _, id := range ids {
				id = strings.TrimSpace(id)
				if id == "" {
					continue
				}
				seen[id] = struct{}{}
			}
			p.allowedIDs[url] = seen
			p.mu.Unlock()
		}
	}
}

func getWithRetry(ctx context.Context, url string, retries int, interval time.Duration) ([]byte, error) {
	if retries < 0 {
		retries = 0
	}
	for i := 0; i < retries; i++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			continue
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			context.LoggerFrom(ctx).Warn("Failed to fetch remote ID list", "url", url, "error", err.Error())
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(interval):
			}
			continue
		}
		defer resp.Body.Close()
		return io.ReadAll(resp.Body)
	}
	return nil, fmt.Errorf("failed to fetch %s after %d retries", url, retries)
}
