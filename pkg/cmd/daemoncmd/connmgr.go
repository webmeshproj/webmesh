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

package daemoncmd

import (
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	v1 "github.com/webmeshproj/api/go/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/webmeshproj/webmesh/pkg/config"
	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/crypto"
	"github.com/webmeshproj/webmesh/pkg/embed"
	"github.com/webmeshproj/webmesh/pkg/meshnet/endpoints"
	"github.com/webmeshproj/webmesh/pkg/meshnet/system/firewall"
	"github.com/webmeshproj/webmesh/pkg/storage"
	"github.com/webmeshproj/webmesh/pkg/storage/errors"
	"github.com/webmeshproj/webmesh/pkg/storage/types"
)

var (
	// ErrNoPortsAvailable is returned when no ports are available.
	ErrNoPortsAvailable = status.Errorf(codes.FailedPrecondition, "no ports available")
	// ErrNoIndexAvailable is returned when no utun index is available.
	ErrNoIndexAvailable = status.Errorf(codes.FailedPrecondition, "no utun index available")
	// ErrNotConnected is returned when the node is not connected to the mesh.
	ErrNotConnected = status.Errorf(codes.FailedPrecondition, "not connected to the specified network")
	// ErrAlreadyConnected is returned when the node is already connected to the mesh.
	ErrAlreadyConnected = status.Errorf(codes.FailedPrecondition, "already connected to the specified network")
	// ErrConnected is returned when the node is connected to the mesh.
	ErrConnected = status.Errorf(codes.FailedPrecondition, "connected to the specified network")
)

// ConnManager manages the connections for the daemon.
type ConnManager struct {
	nodeID   types.NodeID
	key      crypto.PrivateKey
	conf     Config
	profiles ProfileStore
	conns    map[string]embed.Node
	ports    map[uint16]string
	utuns    map[uint16]string
	log      *slog.Logger
	mu       sync.RWMutex
}

// NewConnManager creates a new connection manager.
func NewConnManager(conf Config) (*ConnManager, error) {
	log := conf.NewLogger().With("appdaemon", "connmgr")
	key, err := conf.LoadKey(log)
	if err != nil {
		return nil, fmt.Errorf("load key: %w", err)
	}
	profiles, err := NewProfileStore(func() string {
		if conf.Persistence.Path == "" {
			return ""
		}
		return filepath.Join(conf.Persistence.Path, "profiles")
	}())
	if err != nil {
		return nil, fmt.Errorf("create profile store: %w", err)
	}
	var nodeID types.NodeID
	if conf.NodeID != "" {
		nodeID = types.NodeID(conf.NodeID)
	} else {
		nodeID = types.NodeID(key.ID())
	}
	return &ConnManager{
		nodeID:   nodeID,
		key:      key,
		conf:     conf,
		profiles: profiles,
		conns:    make(map[string]embed.Node),
		ports:    make(map[uint16]string),
		utuns:    make(map[uint16]string),
		log:      log,
	}, nil
}

// NodeID returns the node ID used for connections.
func (m *ConnManager) NodeID() string {
	return m.nodeID.String()
}

// PublicKey returns the encoded public key used for connections.
func (m *ConnManager) PublicKey() string {
	encoded, _ := m.key.PublicKey().Encode()
	return encoded
}

// Profiles returns the profiles store.
func (m *ConnManager) Profiles() ProfileStore {
	return m.profiles
}

// Close closes the connection manager and all connections. It is not
// safe to use the connection manager after calling Close.
func (m *ConnManager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	defer m.profiles.Close()
	for id, conn := range m.conns {
		m.log.Info("Stopping connection", "id", id)
		err := conn.Stop(context.WithLogger(context.Background(), m.log))
		if err != nil {
			m.log.Error("Failed to stop connection", "error", err.Error())
		}
	}
	return nil
}

// ConnIDs returns the IDs of all currently active connections.
func (m *ConnManager) ConnIDs() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.listConnIDs()
}

// Get gets the connection for the given ID.
func (m *ConnManager) Get(connID string) (embed.Node, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	n, ok := m.conns[connID]
	return n, ok
}

// GetStatus returns the status of the connection for the given ID.
func (m *ConnManager) GetStatus(connID string) v1.DaemonConnStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()
	c, ok := m.conns[connID]
	if !ok {
		return v1.DaemonConnStatus_DISCONNECTED
	}
	if c.MeshNode().Started() {
		return v1.DaemonConnStatus_CONNECTED
	}
	return v1.DaemonConnStatus_CONNECTING
}

// GetMeshNode returns the full mesh node for the given ID.
func (m *ConnManager) GetMeshNode(ctx context.Context, connID string) (types.MeshNode, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	conn, ok := m.conns[connID]
	if !ok {
		return types.MeshNode{}, ErrNotConnected
	}
	return conn.Storage().MeshDB().Peers().Get(ctx, conn.MeshNode().ID())
}

// DataDir returns the data directory for the given connection ID.
func (m *ConnManager) DataDir(connID string) string {
	return filepath.Join(m.conf.Persistence.Path, connID)
}

// DropStorage drops storage for the connection with the given ID.
func (m *ConnManager) DropStorage(ctx context.Context, connID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.conns[connID]
	if ok {
		return status.Errorf(codes.FailedPrecondition, "cannot drop storage for running connection")
	}
	if m.conf.Persistence.Path == "" {
		return nil
	}
	err := os.RemoveAll(m.DataDir(connID))
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove all: %w", err)
	}
	return nil
}

// NewConn creates a new connection for the given request. Start must be called
// on the returned node to start the connection.
func (m *ConnManager) NewConn(ctx context.Context, req *v1.ConnectRequest) (id string, node embed.Node, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	connID := req.GetId()
	_, ok := m.conns[connID]
	if ok {
		return "", nil, ErrAlreadyConnected
	}
	if connID == "" {
		var err error
		connID, err = crypto.NewRandomID()
		if err != nil {
			return "", nil, status.Errorf(codes.Internal, "failed to generate connection ID: %v", err)
		}
		m.log.Info("Generated new connection ID", "id", connID)
		// Double check that the ID is unique.
		_, ok := m.conns[connID]
		if ok {
			return "", nil, status.Errorf(codes.Internal, "connection ID collision")
		}
	}
	port, err := m.assignListenPort(connID)
	if err != nil {
		return "", nil, err
	}
	m.log.Info("Creating new webmesh node", "id", connID, "port", port)
	profile, err := m.profiles.Get(ctx, ProfileID(connID))
	if err != nil {
		if errors.IsNotFound(err) {
			return "", nil, status.Errorf(codes.NotFound, "profile not found")
		}
		return "", nil, status.Errorf(codes.Internal, "failed to get profile: %v", err)
	}
	cfg, err := m.buildConnConfig(ctx, profile.ConnectionParameters, connID, port)
	if err != nil {
		return "", nil, err
	}
	m.log.Debug("Generated webmesh node configuration", "id", connID, "config", cfg.ToMapStructure())
	node, err = embed.NewNode(ctx, embed.Options{
		Config: cfg,
		Key:    m.key,
		Logger: m.log.With("connection-id", connID),
	})
	if err != nil {
		return "", nil, status.Errorf(codes.Internal, "failed to create node: %v", err)
	}
	m.conns[connID] = node
	return connID, node, nil
}

// Disconnect disconnects the connection for the given ID.
func (m *ConnManager) Disconnect(ctx context.Context, connID string) error {
	m.mu.RLock()
	conn, ok := m.conns[connID]
	m.mu.RUnlock()
	if !ok {
		return ErrNotConnected
	}
	defer m.RemoveConn(connID)
	return conn.Stop(ctx)
}

// RemoveConn removes the connection for the given ID.
func (m *ConnManager) RemoveConn(connID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.conns, connID)
	delete(m.ports, m.portByConnID(connID))
	if runtime.GOOS == "darwin" {
		delete(m.utuns, m.utunByConnID(connID))
	}
}

func (m *ConnManager) portByConnID(connID string) uint16 {
	for port, id := range m.ports {
		if id == connID {
			return port
		}
	}
	return 0
}

func (m *ConnManager) utunByConnID(connID string) uint16 {
	for index, id := range m.utuns {
		if id == connID {
			return index
		}
	}
	return 0
}

func (m *ConnManager) listConnIDs() []string {
	ids := make([]string, 0, len(m.conns))
	for id := range m.conns {
		ids = append(ids, id)
	}
	return ids
}

func (m *ConnManager) listInterfaceNames() []string {
	names := make([]string, 0)
	for _, conn := range m.conns {
		if !conn.MeshNode().Started() {
			continue
		}
		names = append(names, conn.MeshNode().Network().WireGuard().Name())
	}
	return names
}

func (m *ConnManager) assignListenPort(connID string) (uint16, error) {
	const maxPort = 65535
	port := m.conf.WireGuardStartPort
	for {
		if _, ok := m.ports[port]; !ok {
			m.ports[port] = connID
			return port, nil
		}
		port++
		if port > maxPort {
			return 0, ErrNoPortsAvailable
		}
	}
}

func (m *ConnManager) assignUTUNIndex(connID string) (uint16, error) {
	const maxIndex = 255
	index := uint16(10)
	for {
		if _, ok := m.utuns[index]; !ok {
			m.utuns[index] = connID
			return index, nil
		}
		index++
		if index > maxIndex {
			return 0, ErrNoIndexAvailable
		}
	}
}

func (m *ConnManager) buildConnConfig(ctx context.Context, req *v1.ConnectionParameters, connID string, listenPort uint16) (*config.Config, error) {
	conf := config.NewDefaultConfig(m.nodeID.String())
	conf.Global.LogLevel = m.conf.LogLevel
	conf.Global.LogFormat = m.conf.LogFormat
	conf.Storage.LogLevel = m.conf.LogLevel
	conf.Storage.LogFormat = m.conf.LogFormat
	conf.Storage.InMemory = true
	if m.conf.Persistence.Path != "" {
		conf.Storage.InMemory = false
		conf.Storage.Path = m.DataDir(connID)
	}
	conf.WireGuard.ListenPort = int(listenPort)
	var eps endpoints.PrefixList
	if len(req.GetNetworking().GetEndpoints()) > 0 {
		for _, addrstr := range req.GetNetworking().GetEndpoints() {
			addr, err := netip.ParseAddr(addrstr)
			if err != nil {
				return nil, status.Errorf(codes.InvalidArgument, "invalid endpoint address: %v", err)
			}
			var prefix int
			if addr.Is4() {
				prefix = 32
			} else {
				prefix = 128
			}
			eps = append(eps, netip.PrefixFrom(addr, prefix))
		}
	}
	if req.GetNetworking().GetDetectEndpoints() {
		detected, err := endpoints.Detect(ctx, endpoints.DetectOpts{
			DetectIPv6:     true,
			DetectPrivate:  req.GetNetworking().GetDetectPrivateEndpoints(),
			SkipInterfaces: m.listInterfaceNames(),
		})
		if err != nil {
			return nil, status.Errorf(codes.Internal, "failed to detect endpoints: %v", err)
		}
		eps = append(eps, detected...)
	}
	// Set the primary endpoint to any public addresses.
	// TODO: Make this configurable.
	if eps.FirstPublicAddr().IsValid() {
		conf.Mesh.PrimaryEndpoint = eps.FirstPublicAddr().String()
	}
	// Set all endpoints as wireguard endpoints.
	for _, addrport := range eps.AddrPorts(listenPort) {
		conf.WireGuard.Endpoints = append(conf.WireGuard.Endpoints, addrport.String())
	}
	if runtime.GOOS != "darwin" {
		// Set a unique interface name on non-darwin systems.
		conf.WireGuard.InterfaceName = connID + "0"
	} else {
		tunindex, err := m.assignUTUNIndex(connID)
		if err != nil {
			return nil, err
		}
		conf.WireGuard.InterfaceName = fmt.Sprintf("utun%d", tunindex)
	}
	conf.Mesh.UseMeshDNS = req.GetNetworking().GetUseDNS()
	conf.Bootstrap.Enabled = req.GetBootstrap().GetEnabled()
	if conf.Bootstrap.Enabled {
		conf.Bootstrap.Admin = m.nodeID.String()
		conf.Bootstrap.DisableRBAC = !req.GetBootstrap().GetRbacEnabled()
		conf.Bootstrap.IPv4Network = storage.DefaultIPv4Network
		conf.Bootstrap.MeshDomain = storage.DefaultMeshDomain
		if req.GetBootstrap().GetIpv4Network() != "" {
			conf.Bootstrap.IPv4Network = req.GetBootstrap().GetIpv4Network()
		}
		if req.GetBootstrap().GetDomain() != "" {
			conf.Bootstrap.MeshDomain = req.GetBootstrap().GetDomain()
		}
		switch req.GetBootstrap().GetDefaultNetworkACL() {
		case v1.MeshConnBootstrap_ACCEPT:
			conf.Bootstrap.DefaultNetworkPolicy = string(firewall.PolicyAccept)
		case v1.MeshConnBootstrap_DROP:
			conf.Bootstrap.DefaultNetworkPolicy = string(firewall.PolicyDrop)
		default:
			conf.Bootstrap.DefaultNetworkPolicy = string(firewall.PolicyAccept)
		}
		// We only support single node bootstrap for now, so set the initial leader election
		// timeouts to a very low value
		conf.Bootstrap.ElectionTimeout = time.Millisecond * 500
	}
	conf.TLS.Insecure = !req.GetTls().GetEnabled()
	if !conf.TLS.Insecure {
		if len(req.GetTls().GetCaCertData()) != 0 {
			conf.TLS.CAData = req.GetTls().GetCaCertData()
		}
		conf.TLS.VerifyChainOnly = req.GetTls().GetVerifyChainOnly()
		conf.TLS.InsecureSkipVerify = req.GetTls().GetSkipVerify()
	}
	switch req.GetAddrType() {
	case v1.ConnectionParameters_ADDR:
		conf.Mesh.JoinAddresses = req.GetAddrs()
	case v1.ConnectionParameters_RENDEZVOUS:
		conf.Discovery.Discover = true
		conf.Discovery.Rendezvous = req.GetAddrs()[0]
	case v1.ConnectionParameters_MULTIADDR:
		conf.Mesh.JoinMultiaddrs = req.GetAddrs()
	}
	switch req.GetAuthMethod() {
	case v1.NetworkAuthMethod_NO_AUTH:
	case v1.NetworkAuthMethod_BASIC:
		conf.Auth.Basic.Username = req.GetAuthCredentials()[v1.ConnectionParameters_BASIC_USERNAME.String()]
		conf.Auth.Basic.Password = req.GetAuthCredentials()[v1.ConnectionParameters_BASIC_PASSWORD.String()]
	case v1.NetworkAuthMethod_LDAP:
		conf.Auth.LDAP.Username = req.GetAuthCredentials()[v1.ConnectionParameters_LDAP_USERNAME.String()]
		conf.Auth.LDAP.Password = req.GetAuthCredentials()[v1.ConnectionParameters_LDAP_PASSWORD.String()]
	case v1.NetworkAuthMethod_MTLS:
		conf.Auth.MTLS.CertData = req.GetTls().GetCertData()
		conf.Auth.MTLS.KeyData = req.GetTls().GetKeyData()
	case v1.NetworkAuthMethod_ID:
		conf.Auth.IDAuth.Enabled = true
	}
	conf.Services.API.Disabled = !req.GetServices().GetEnabled()
	if !conf.Services.API.Disabled {
		conf.Services.API.DisableLeaderProxy = true
		conf.Services.API.ListenAddress = req.GetServices().GetListenAddress()
		conf.Services.API.LibP2P.Enabled = req.GetServices().GetEnableLibP2P()
		conf.Services.API.LibP2P.LocalAddrs = req.GetServices().GetListenMultiaddrs()
		conf.Services.API.LibP2P.Rendezvous = req.GetServices().GetRendezvous()
		if len(conf.Services.API.LibP2P.Rendezvous) > 0 {
			conf.Services.API.LibP2P.Announce = true
		}
		conf.Services.API.Insecure = !req.GetServices().GetEnableTLS()
		if len(req.GetTls().GetCertData()) != 0 {
			conf.Services.API.TLSCertData = req.GetTls().GetCertData()
		}
		if len(req.GetTls().GetKeyData()) != 0 {
			conf.Services.API.TLSKeyData = req.GetTls().GetKeyData()
		}
		conf.Plugins.Configs = make(map[string]config.PluginConfig)
		switch req.GetServices().GetAuthMethod() {
		case v1.NetworkAuthMethod_NO_AUTH:
		case v1.NetworkAuthMethod_ID:
			conf.Plugins.Configs["id-auth"] = config.PluginConfig{
				Config: map[string]any{}, // TODO: Support ID auth configurations.
			}
		case v1.NetworkAuthMethod_MTLS:
			conf.Plugins.Configs["mtls"] = config.PluginConfig{
				Config: map[string]any{
					"ca-data": req.GetTls().GetCaCertData(),
				},
			}
		}
		for _, feature := range req.GetServices().GetFeatures() {
			switch feature {
			case v1.Feature_LEADER_PROXY:
				conf.Services.API.DisableLeaderProxy = false
			case v1.Feature_MESH_API:
				conf.Services.API.MeshEnabled = true
			case v1.Feature_ADMIN_API:
				conf.Services.API.AdminEnabled = true
			case v1.Feature_MEMBERSHIP:
				conf.Mesh.RequestVote = true
			case v1.Feature_ICE_NEGOTIATION:
				conf.Services.WebRTC.Enabled = true
				// TODO: Support custom STUN servers
			case v1.Feature_STORAGE_QUERIER:
				conf.Mesh.RequestObserver = true
			}
		}
	}
	if req.GetServices().GetDns().GetEnabled() {
		conf.Services.MeshDNS.Enabled = true
		if req.GetServices().GetDns().GetListenUDP() != "" {
			conf.Services.MeshDNS.ListenUDP = req.GetServices().GetDns().GetListenUDP()
		}
		if req.GetServices().GetDns().GetListenTCP() != "" {
			conf.Services.MeshDNS.ListenTCP = req.GetServices().GetDns().GetListenTCP()
		}
	}
	return conf, nil
}
