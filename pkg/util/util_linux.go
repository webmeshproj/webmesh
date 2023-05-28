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

package util

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	v1 "github.com/webmeshproj/api/v1"
	"golang.org/x/sys/unix"
	"pault.ag/go/modprobe"
)

// Modprobe loads the given kernel module.
func Modprobe(name, params string) error {
	return modprobe.Load(name, params)
}

// Rmmod unloads the given kernel module.
func Rmmod(name string) error {
	return modprobe.Remove(name)
}

// LoadAverage returns the load average.
func LoadAverage() (*v1.LoadAverage, error) {
	data, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return nil, fmt.Errorf("failed to read load average: %w", err)
	}
	fields := strings.Fields(string(data))
	if len(fields) < 3 {
		return nil, fmt.Errorf("invalid load average: %s", data)
	}
	one, err := strconv.ParseFloat(fields[0], 32)
	if err != nil {
		return nil, fmt.Errorf("failed to parse load average: %w", err)
	}
	five, err := strconv.ParseFloat(fields[1], 32)
	if err != nil {
		return nil, fmt.Errorf("failed to parse load average: %w", err)
	}
	fifteen, err := strconv.ParseFloat(fields[2], 32)
	if err != nil {
		return nil, fmt.Errorf("failed to parse load average: %w", err)
	}
	return &v1.LoadAverage{
		One:     float32(one),
		Five:    float32(five),
		Fifteen: float32(fifteen),
	}, nil
}

// MountPaths returns a map of mount paths to device paths.
func MountPaths() (map[string]string, error) {
	f, err := os.Open("/proc/mounts")
	if err != nil {
		return nil, fmt.Errorf("failed to open /proc/mounts: %w", err)
	}
	defer f.Close()
	paths := make(map[string]string)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 {
			return nil, fmt.Errorf("invalid mount entry: %s", scanner.Text())
		}
		device := fields[0]
		path := fields[1]
		if device != "tmpfs" && !strings.HasPrefix(device, "/dev") {
			continue
		}
		paths[path] = device
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to scan /proc/mounts: %w", err)
	}
	return paths, nil
}

// DiskUsage returns the disk usage for the given path.
func DiskUsage(path string) (*v1.DiskInfo, error) {
	var fsstat unix.Statfs_t
	if err := unix.Statfs(path, &fsstat); err != nil {
		return nil, fmt.Errorf("failed to statfs %s: %w", path, err)
	}
	total := fsstat.Blocks * uint64(fsstat.Bsize)
	free := fsstat.Bfree * uint64(fsstat.Bsize)
	used := total - free
	usedPercent := float32(used) / float32(total) * 100
	inodesTotal := fsstat.Files
	inodesFree := fsstat.Ffree
	inodesUsed := inodesTotal - inodesFree
	inodesUsedPercent := float32(inodesUsed) / float32(inodesTotal) * 100
	return &v1.DiskInfo{
		FilesystemPath:    path,
		Total:             total,
		Free:              free,
		Used:              used,
		UsedPercent:       usedPercent,
		InodesTotal:       inodesTotal,
		InodesFree:        inodesFree,
		InodesUsed:        inodesUsed,
		InodesUsedPercent: inodesUsedPercent,
	}, nil
}
