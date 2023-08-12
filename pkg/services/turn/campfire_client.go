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
	"crypto/aes"
	"crypto/cipher"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/pion/webrtc/v3"
)

// CampfireClient represents a client that can communicate with a TURN server
// supporting campfire.
type CampfireClient struct {
	opts       CampfireClientOptions
	crypter    cipher.BlockMode
	decrypter  cipher.BlockMode
	conn       *net.UDPConn
	offers     chan CampfireOffer
	answers    chan CampfireAnswer
	candidates chan CampfireCandidate
	errc       chan error
	closec     chan struct{}
	log        *slog.Logger
}

// CampfireClientOptions represents options for a CampfireClient.
type CampfireClientOptions struct {
	// Addr is the address of the STUN/TURN server.
	Addr string
	// Ufrag is the username fragment to use when communicating with the server.
	Ufrag string
	// Pwd is the password to use when communicating with the server.
	Pwd string
	// PSK is the pre-shared key used for encrypting/decrypting the data in sent/received
	// messages.
	PSK []byte
}

// CampfireOffer represents an offer that was received from a peer.
type CampfireOffer struct {
	Ufrag string
	Pwd   string
	SDP   webrtc.SessionDescription
}

// CampfireAnswer represents an answer that was received from a peer.
type CampfireAnswer struct {
	Ufrag string
	Pwd   string
	SDP   webrtc.SessionDescription
}

// CampfireCandidate represents a candidate that was received from a peer.
type CampfireCandidate struct {
	Ufrag string
	Pwd   string
	Cand  webrtc.ICECandidateInit
}

// NewCampfireClient creates a new CampfireClient.
func NewCampfireClient(opts CampfireClientOptions) (*CampfireClient, error) {
	addr := strings.TrimPrefix(opts.Addr, "turn:")
	addr = strings.TrimPrefix(addr, "stun:")
	block, err := aes.NewCipher(opts.PSK)
	if err != nil {
		return nil, err
	}
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		return nil, err
	}
	cli := &CampfireClient{
		opts:       opts,
		crypter:    cipher.NewCBCEncrypter(block, opts.PSK[:aes.BlockSize]),
		decrypter:  cipher.NewCBCDecrypter(block, opts.PSK[:aes.BlockSize]),
		conn:       conn,
		offers:     make(chan CampfireOffer, 10),
		answers:    make(chan CampfireAnswer, 10),
		candidates: make(chan CampfireCandidate, 10),
		errc:       make(chan error, 1),
		closec:     make(chan struct{}),
		log:        slog.Default().With("component", "campfire-client"),
	}
	go cli.handleIncoming()
	return cli, nil
}

// Close closes the client.
func (c *CampfireClient) Close() error {
	return c.conn.Close()
}

// Announce announces interest in offers containing the given ufrag and pwd.
func (c *CampfireClient) Announce(ufrag, pwd string) error {
	msg := CampfireMessage{
		LUfrag: c.opts.Ufrag,
		LPwd:   c.opts.Pwd,
		RUfrag: ufrag,
		RPwd:   pwd,
		Type:   CampfireMessageAnnounce,
	}
	data, err := msg.Encode()
	if err != nil {
		return err
	}
	_, err = c.conn.Write(data)
	if err != nil {
		return err
	}
	return nil
}

// Offers returns a channel of offers received from peers.
func (c *CampfireClient) Offers() <-chan CampfireOffer {
	return c.offers
}

// Answers returns a channel of answers received from peers.
func (c *CampfireClient) Answers() <-chan CampfireAnswer {
	return c.answers
}

// Candidates returns a channel of candidates received from peers.
func (c *CampfireClient) Candidates() <-chan CampfireCandidate {
	return c.candidates
}

// Errors returns a channel of errors.
func (c *CampfireClient) Errors() <-chan error {
	return c.errc
}

// SendOffer sends an offer to the peer with the given ufrag and pwd.
func (c *CampfireClient) SendOffer(ufrag, pwd string, offer webrtc.SessionDescription) error {
	sdp, err := json.Marshal(offer)
	if err != nil {
		return err
	}
	msg := CampfireMessage{
		LUfrag: c.opts.Ufrag,
		LPwd:   c.opts.Pwd,
		RUfrag: ufrag,
		RPwd:   pwd,
		Type:   CampfireMessageOffer,
		Data:   c.encryptData(sdp),
	}
	data, err := msg.Encode()
	if err != nil {
		return err
	}
	_, err = c.conn.Write(data)
	if err != nil {
		return err
	}
	return nil
}

// SendAnswer sends an answer to the peer with the given ufrag and pwd.
func (c *CampfireClient) SendAnswer(ufrag, pwd string, answer webrtc.SessionDescription) error {
	sdp, err := json.Marshal(answer)
	if err != nil {
		return err
	}
	msg := CampfireMessage{
		LUfrag: c.opts.Ufrag,
		LPwd:   c.opts.Pwd,
		RUfrag: ufrag,
		RPwd:   pwd,
		Type:   CampfireMessageAnswer,
		Data:   c.encryptData(sdp),
	}
	data, err := msg.Encode()
	if err != nil {
		return err
	}
	_, err = c.conn.Write(data)
	if err != nil {
		return err
	}
	return nil
}

// SendCandidate sends a candidate to the peer with the given ufrag and pwd.
func (c *CampfireClient) SendCandidate(ufrag, pwd string, candidate *webrtc.ICECandidate) error {
	if candidate == nil {
		return nil
	}
	cand, err := json.Marshal(candidate.ToJSON())
	if err != nil {
		return err
	}
	msg := CampfireMessage{
		LUfrag: c.opts.Ufrag,
		LPwd:   c.opts.Pwd,
		RUfrag: ufrag,
		RPwd:   pwd,
		Type:   CampfireMessageICE,
		Data:   c.encryptData(cand),
	}
	data, err := msg.Encode()
	if err != nil {
		return err
	}
	_, err = c.conn.Write(data)
	if err != nil {
		return err
	}
	return nil
}

func (c *CampfireClient) handleIncoming() {
	for {
		select {
		case <-c.closec:
			return
		default:
		}
		err := c.conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		if err != nil {
			c.errc <- err
			return
		}
		data := make([]byte, 4096)
		n, _, err := c.conn.ReadFromUDP(data)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			} else if errors.Is(err, net.ErrClosed) {
				return
			}
			c.errc <- err
			return
		}
		var msg CampfireMessage
		err = msg.Decode(data[:n])
		if err != nil {
			c.errc <- err
			return
		}
		switch msg.Type {
		case CampfireMessageOffer:
			data, err := c.decryptData(msg.Data)
			if err != nil {
				c.log.Warn("failed to decrypt offer", "err", err)
				continue
			}
			var offer webrtc.SessionDescription
			err = json.Unmarshal(data, &offer)
			if err != nil {
				c.errc <- fmt.Errorf("failed to unmarshal offer: %w", err)
				return
			}
			c.offers <- CampfireOffer{
				Ufrag: msg.LUfrag,
				Pwd:   msg.LPwd,
				SDP:   offer,
			}
		case CampfireMessageAnswer:
			data, err := c.decryptData(msg.Data)
			if err != nil {
				c.log.Warn("failed to decrypt answer", "err", err)
				continue
			}
			var answer webrtc.SessionDescription
			err = json.Unmarshal(data, &answer)
			if err != nil {
				c.errc <- fmt.Errorf("failed to unmarshal answer: %w", err)
				return
			}
			c.answers <- CampfireAnswer{
				Ufrag: msg.LUfrag,
				Pwd:   msg.LPwd,
				SDP:   answer,
			}
		case CampfireMessageICE:
			data, err := c.decryptData(msg.Data)
			if err != nil {
				c.log.Warn("failed to decrypt candidate", "err", err)
				continue
			}
			var candidate webrtc.ICECandidateInit
			err = json.Unmarshal(data, &candidate)
			if err != nil {
				c.errc <- fmt.Errorf("failed to unmarshal candidate: %w", err)
				return
			}
			c.candidates <- CampfireCandidate{
				Ufrag: msg.LUfrag,
				Pwd:   msg.LPwd,
				Cand:  candidate,
			}
		}
	}
}

func (c *CampfireClient) encryptData(data []byte) []byte {
	// Pad data to block size
	bs := c.crypter.BlockSize()
	if len(data)%bs != 0 {
		pad := bs - (len(data) % bs)
		data = append(data, bytes.Repeat([]byte{0}, pad)...)
	}
	out := make([]byte, len(data))
	c.crypter.CryptBlocks(out, data)
	return out
}

func (c *CampfireClient) decryptData(data []byte) ([]byte, error) {
	bs := c.decrypter.BlockSize()
	if len(data)%bs != 0 {
		return nil, errors.New("invalid data length")
	}
	plaintext := make([]byte, len(data))
	c.decrypter.CryptBlocks(plaintext, data)
	plaintext = bytes.TrimRight(plaintext, "\x00")
	return plaintext, nil
}
