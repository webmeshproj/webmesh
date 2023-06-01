/*
Copyright 2023.

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

package wireguard

import (
	"time"

	"github.com/elastic/go-sysinfo"
	v1 "github.com/webmeshproj/api/v1"
	"golang.org/x/exp/slog"

	"github.com/webmeshproj/node/pkg/util"
)

// Metrics returns the metrics for the wireguard interface and the host.
func (w *wginterface) Metrics() (*v1.NodeMetrics, error) {
	device, err := w.cli.Device(w.Name())
	if err != nil {
		return nil, err
	}
	metrics := &v1.NodeMetrics{
		DeviceName:         device.Name,
		PublicKey:          device.PublicKey.String(),
		AddressV4:          w.Interface.AddressV4().String(),
		AddressV6:          w.Interface.AddressV6().String(),
		Type:               device.Type.String(),
		ListenPort:         int32(device.ListenPort),
		TotalReceiveBytes:  0,
		TotalTransmitBytes: 0,
		Peers:              make([]*v1.PeerMetrics, len(device.Peers)),
	}
	for i, peer := range device.Peers {
		metrics.TotalReceiveBytes += uint64(peer.ReceiveBytes)
		metrics.TotalTransmitBytes += uint64(peer.TransmitBytes)
		metrics.Peers[i] = &v1.PeerMetrics{
			PublicKey:           peer.PublicKey.String(),
			Endpoint:            peer.Endpoint.String(),
			PersistentKeepAlive: peer.PersistentKeepaliveInterval.String(),
			LastHandshakeTime:   peer.LastHandshakeTime.UTC().Format(time.RFC3339),
			AllowedIps: func() []string {
				var ips []string
				for _, ip := range peer.AllowedIPs {
					ips = append(ips, ip.String())
				}
				return ips
			}(),
			ProtocolVersion: int64(peer.ProtocolVersion),
			ReceiveBytes:    uint64(peer.ReceiveBytes),
			TransmitBytes:   uint64(peer.TransmitBytes),
		}
	}
	host, err := sysinfo.Host()
	if err != nil {
		w.log.Error("failed to get host info", slog.String("error", err.Error()))
		return metrics, nil
	}
	info := host.Info()
	// Build out base system info
	metrics.System = &v1.HostMetrics{
		Cpu:    &v1.CPUTimes{},
		Memory: &v1.MemoryInfo{},
		Host: &v1.HostInfo{
			Architecture: info.Architecture,
			BootTime:     info.BootTime.UTC().Format(time.RFC3339),
			Containerized: func() bool {
				if info.Containerized != nil {
					return *info.Containerized
				}
				return false
			}(),
			Hostname:      info.Hostname,
			Ips:           info.IPs,
			KernelVersion: info.KernelVersion,
			Macs:          info.MACs,
			Os: &v1.OSInfo{
				Type:     info.OS.Type,
				Family:   info.OS.Family,
				Platform: info.OS.Platform,
				Name:     info.OS.Name,
				Version:  info.OS.Version,
				Major:    int64(info.OS.Major),
				Minor:    int64(info.OS.Minor),
				Patch:    int64(info.OS.Patch),
				Build:    info.OS.Build,
				Codename: info.OS.Codename,
			},
			Timezone: info.Timezone,
			Uptime:   info.Uptime().String(),
		},
	}
	// CPU and load average
	cpuTimes, err := host.CPUTime()
	if err != nil {
		w.log.Error("failed to get cpu times", slog.String("error", err.Error()))
	} else {
		metrics.System.Cpu = &v1.CPUTimes{
			User:    cpuTimes.User.String(),
			System:  cpuTimes.System.String(),
			Idle:    cpuTimes.Idle.String(),
			IoWait:  cpuTimes.IOWait.String(),
			Irq:     cpuTimes.IRQ.String(),
			Nice:    cpuTimes.Nice.String(),
			SoftIrq: cpuTimes.SoftIRQ.String(),
			Steal:   cpuTimes.Steal.String(),
		}
	}
	loadAverage, err := util.LoadAverage()
	if err != nil {
		w.log.Error("failed to get load average", slog.String("error", err.Error()))
	} else {
		metrics.System.Cpu.LoadAverage = loadAverage
	}
	// Memory usage
	mem, err := host.Memory()
	if err != nil {
		w.log.Error("failed to get memory info", slog.String("error", err.Error()))
		return metrics, nil
	}
	metrics.System.Memory = &v1.MemoryInfo{
		Total:        mem.Total,
		Used:         mem.Used,
		Available:    mem.Available,
		Free:         mem.Free,
		VirtualTotal: mem.VirtualTotal,
		VirtualUsed:  mem.VirtualUsed,
		VirtualFree:  mem.VirtualFree,
	}
	// Disk usage
	mounts, err := util.MountPaths()
	if err != nil {
		w.log.Error("failed to get mount paths", slog.String("error", err.Error()))
		return metrics, nil
	}
	metrics.System.Disks = make([]*v1.DiskInfo, 0)
	for path, device := range mounts {
		diskMetrics, err := util.DiskUsage(path)
		if err != nil {
			w.log.Error("failed to get disk usage", slog.String("error", err.Error()))
			continue
		}
		diskMetrics.Device = device
		metrics.System.Disks = append(metrics.System.Disks, diskMetrics)
	}
	return metrics, nil
}
