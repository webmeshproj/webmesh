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

package turn

import (
	"errors"

	v1 "github.com/webmeshproj/api/v1"
	"google.golang.org/protobuf/proto"
)

// IsCampfireMessage returns true if the given packet is a campfire message.
func IsCampfireMessage(p []byte) bool {
	_, err := DecodeCampfireMessage(p)
	return err == nil
}

// EncodeCampfireMessage encodes a campfire message.
func EncodeCampfireMessage(msg *v1.CampfireMessage) ([]byte, error) {
	return proto.Marshal(msg)
}

// DecodeCampfireMessage decodes a campfire message.
func DecodeCampfireMessage(p []byte) (*v1.CampfireMessage, error) {
	var msg v1.CampfireMessage
	err := proto.Unmarshal(p, &msg)
	return &msg, err
}

// ValidateCampfireMessage validates a campfire message.
func ValidateCampfireMessage(msg *v1.CampfireMessage) error {
	if msg.Id == "" && msg.Type != v1.CampfireMessage_ANNOUNCE {
		return errors.New("missing id")
	}
	if msg.Lufrag == "" {
		return errors.New("missing lufrag")
	}
	if msg.Lpwd == "" {
		return errors.New("missing lpwd")
	}
	if msg.Rufrag == "" {
		return errors.New("missing rufrag")
	}
	if msg.Rpwd == "" {
		return errors.New("missing rpwd")
	}
	if _, ok := v1.CampfireMessage_MessageType_name[int32(msg.Type)]; !ok {
		return errors.New("invalid message type")
	} else if msg.Type == v1.CampfireMessage_UNKNOWN {
		return errors.New("unknown message type")
	}
	return nil
}
