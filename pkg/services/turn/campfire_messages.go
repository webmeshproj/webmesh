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
	"bytes"
	"encoding/gob"
	"errors"
	"time"
)

// CampfireMessagePrefix is the prefix for campfire messages.
const CampfireMessagePrefix = "CAMPFIRE\n"

// CampfireMessageType is the type of message sent over campfire.
type CampfireMessageType int

const (
	// CampfireMessageAnnounce is a message type announcing presence
	CampfireMessageAnnounce CampfireMessageType = iota + 1
	// CampfireMessageOffer is a message type for an offer
	CampfireMessageOffer
	// CampfireMessageAnswer is a message type for an answer
	CampfireMessageAnswer
	// CampfireMessageICE is a message type for an ICE candidate
	CampfireMessageICE
)

// IsValid returns true if the message type is valid.
func (c CampfireMessageType) IsValid() bool {
	return c >= CampfireMessageAnnounce && c <= CampfireMessageICE
}

// String returns the string representation of the message type.
func (c CampfireMessageType) String() string {
	switch c {
	case CampfireMessageAnnounce:
		return "announce"
	case CampfireMessageOffer:
		return "offer"
	case CampfireMessageAnswer:
		return "answer"
	case CampfireMessageICE:
		return "ice"
	default:
		return "unknown"
	}
}

// CampfireMessage is a message sent over campfire.
type CampfireMessage struct {
	LUfrag string
	LPwd   string
	RUfrag string
	RPwd   string
	Type   CampfireMessageType
	Data   []byte

	expires int64
}

// IsCampfireMessage returns true if the given bytes are a campfire message.
func IsCampfireMessage(p []byte) bool {
	return bytes.HasPrefix(p, []byte(CampfireMessagePrefix))
}

// DecodeCampfireMessage decodes the given bytes into a campfire message.
func DecodeCampfireMessage(p []byte) (*CampfireMessage, error) {
	var msg CampfireMessage
	err := msg.Decode(p)
	return &msg, err
}

// Encode encodes the message into bytes.
func (c *CampfireMessage) Encode() ([]byte, error) {
	var buf bytes.Buffer
	err := gob.NewEncoder(&buf).Encode(c)
	if err != nil {
		return nil, err
	}
	return append([]byte(CampfireMessagePrefix), buf.Bytes()...), nil
}

// Decode decodes the message from bytes.
func (c *CampfireMessage) Decode(p []byte) error {
	data := bytes.TrimPrefix(p, []byte(CampfireMessagePrefix))
	err := gob.NewDecoder(bytes.NewReader(data)).Decode(c)
	c.expires = time.Now().Truncate(time.Hour).Add(time.Hour).Unix()
	return err
}

// Validate validates the message.
func (c *CampfireMessage) Validate() error {
	if !c.Type.IsValid() {
		return errors.New("invalid type")
	}
	if c.LUfrag == "" {
		return errors.New("missing lufrag")
	}
	if c.LPwd == "" {
		return errors.New("missing lpwd")
	}
	if c.RUfrag == "" {
		return errors.New("missing rufrag")
	}
	if c.RPwd == "" {
		return errors.New("missing rpwd")
	}
	return nil
}

// Expired returns true if the message has expired.
func (c *CampfireMessage) Expired() bool {
	return time.Now().Unix() > c.expires
}
