package nat64

import (
	"net"
)

// EthernetFrame represents an Ethernet frame
type EthernetFrame struct {
	DestinationMAC net.HardwareAddr
	SourceMAC      net.HardwareAddr
	EtherType      uint16
	Payload        []byte
}

// MarshalBinary serializes the Ethernet frame into a byte slice
func (f *EthernetFrame) MarshalBinary() ([]byte, error) {
	frameBytes := make([]byte, 14+len(f.Payload))
	copy(frameBytes[0:6], f.DestinationMAC)
	copy(frameBytes[6:12], f.SourceMAC)
	frameBytes[12] = byte(f.EtherType >> 8)
	frameBytes[13] = byte(f.EtherType)
	copy(frameBytes[14:], f.Payload)
	return frameBytes, nil
}
