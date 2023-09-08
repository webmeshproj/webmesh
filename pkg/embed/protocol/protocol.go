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

// Package protocol defines the libp2p webmesh protocol.
package protocol

import (
	"encoding/base64"

	"github.com/multiformats/go-multiaddr"
)

func init() {
	if err := multiaddr.AddProtocol(Protocol); err != nil {
		panic(err)
	}
}

// ProtocolCode is the code for the webmesh libp2p protocol.
const ProtocolCode = 613

// Protocol is the webmesh libp2p protocol.
var Protocol = multiaddr.Protocol{
	Name:       "webmesh",
	Code:       ProtocolCode,
	VCode:      multiaddr.CodeToVarint(ProtocolCode),
	Size:       -1,
	Path:       true,
	Transcoder: multiaddr.NewTranscoderFromFunctions(protocolStrToBytes, protocolBytesToStr, validateBytes),
}

func protocolStrToBytes(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

func protocolBytesToStr(b []byte) (string, error) {
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func validateBytes(b []byte) error {
	_, err := base64.RawURLEncoding.DecodeString(string(b))
	return err
}
