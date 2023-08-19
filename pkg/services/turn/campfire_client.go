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
	"crypto/aes"
	"crypto/cipher"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/pion/webrtc/v3"
	v1 "github.com/webmeshproj/api/v1"
)

// CampfireClient represents a client that can communicate with a TURN server
// supporting campfire.
type CampfireClient struct {
	id         string
	opts       CampfireClientOptions
	cipher     cipher.AEAD
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
	// ID is a unique identifier for the client. If left unset, a random ID will be
	// generated.
	ID string
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
	// ID contains the ID of the peer that sent the offer.
	ID string
	// Ufrag contains the username fragment of the peer that sent the offer.
	Ufrag string
	// Pwd contains the password of the peer that sent the offer.
	Pwd string
	// SDP contains the SDP of the offer.
	SDP webrtc.SessionDescription
}

// CampfireAnswer represents an answer that was received from a peer.
type CampfireAnswer struct {
	// ID contains the ID of the negotiation. This will always be the same as the client ID.
	ID string
	// Ufrag contains the username fragment of the peer that sent the answer.
	Ufrag string
	// Pwd contains the password of the peer that sent the answer.
	Pwd string
	// SDP contains the SDP of the answer.
	SDP webrtc.SessionDescription
}

// CampfireCandidate represents a candidate that was received from a peer.
type CampfireCandidate struct {
	// ID contains the ID of the peer that initiated the negotiation.
	ID string
	// Ufrag contains the username fragment of the peer that sent the candidate.
	Ufrag string
	// Pwd contains the password of the peer that sent the candidate.
	Pwd string
	// Cand contains the candidate.
	Cand webrtc.ICECandidateInit
}

// NewCampfireClient creates a new CampfireClient.
func NewCampfireClient(opts CampfireClientOptions) (*CampfireClient, error) {
	addr := strings.TrimPrefix(opts.Addr, "turn:")
	addr = strings.TrimPrefix(addr, "stun:")
	parts := strings.Split(addr, "@")
	if len(parts) == 2 {
		addr = parts[1]
	}
	if !strings.Contains(addr, ":") {
		// Add default port if missing.
		addr = addr + ":443"
	}
	if opts.ID == "" {
		id, err := uuid.NewRandom()
		if err != nil {
			return nil, fmt.Errorf("generate random ID: %w", err)
		}
		opts.ID = id.String()
	}
	block, err := aes.NewCipher(opts.PSK)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("resolve UDP address: %w", err)
	}
	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		return nil, fmt.Errorf("dial UDP: %w", err)
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}
	cli := &CampfireClient{
		id:         opts.ID,
		opts:       opts,
		cipher:     aesgcm,
		conn:       conn,
		offers:     make(chan CampfireOffer, 10),
		answers:    make(chan CampfireAnswer, 10),
		candidates: make(chan CampfireCandidate, 10),
		errc:       make(chan error, 10),
		closec:     make(chan struct{}),
		log:        slog.Default().With("component", "campfire-client"),
	}
	go cli.handleIncoming()
	return cli, nil
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

// Close closes the client.
func (c *CampfireClient) Close() error {
	return c.conn.Close()
}

// Announce announces interest in offers containing the given ufrag and pwd.
func (c *CampfireClient) Announce(ufrag, pwd string) error {
	data, err := EncodeCampfireMessage(&v1.CampfireMessage{
		Id:     c.id,
		Lufrag: c.opts.Ufrag,
		Lpwd:   c.opts.Pwd,
		Rufrag: ufrag,
		Rpwd:   pwd,
		Type:   v1.CampfireMessage_ANNOUNCE,
	})
	if err != nil {
		return fmt.Errorf("encode announce message: %w", err)
	}
	_, err = c.conn.Write(data)
	if err != nil {
		return fmt.Errorf("write announce message: %w", err)
	}
	return nil
}

// SendOffer sends an offer to the peer with the given ufrag and pwd.
func (c *CampfireClient) SendOffer(ufrag, pwd string, offer webrtc.SessionDescription) error {
	sdp, err := json.Marshal(offer)
	if err != nil {
		return err
	}
	data, err := EncodeCampfireMessage(&v1.CampfireMessage{
		Id:     c.id,
		Lufrag: c.opts.Ufrag,
		Lpwd:   c.opts.Pwd,
		Rufrag: ufrag,
		Rpwd:   pwd,
		Type:   v1.CampfireMessage_OFFER,
		Data:   c.encryptData(sdp),
	})
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
func (c *CampfireClient) SendAnswer(offerID, ufrag, pwd string, answer webrtc.SessionDescription) error {
	sdp, err := json.Marshal(answer)
	if err != nil {
		return err
	}
	data, err := EncodeCampfireMessage(&v1.CampfireMessage{
		Id:     offerID,
		Lufrag: c.opts.Ufrag,
		Lpwd:   c.opts.Pwd,
		Rufrag: ufrag,
		Rpwd:   pwd,
		Type:   v1.CampfireMessage_ANSWER,
		Data:   c.encryptData(sdp),
	})
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
// If offerID is empty, the local ID is used.
func (c *CampfireClient) SendCandidate(offerID, ufrag, pwd string, candidate *webrtc.ICECandidate) error {
	if candidate == nil {
		return nil
	}
	cand, err := json.Marshal(candidate.ToJSON())
	if err != nil {
		return err
	}
	if offerID == "" {
		offerID = c.id
	}
	data, err := EncodeCampfireMessage(&v1.CampfireMessage{
		Id:     offerID,
		Lufrag: c.opts.Ufrag,
		Lpwd:   c.opts.Pwd,
		Rufrag: ufrag,
		Rpwd:   pwd,
		Type:   v1.CampfireMessage_CANDIDATE,
		Data:   c.encryptData(cand),
	})
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
		if !IsCampfireMessage(data[:n]) {
			continue
		}
		msg, err := DecodeCampfireMessage(data[:n])
		if err != nil {
			c.errc <- err
			continue
		}
		var msgData []byte
		if len(msg.Data) > 0 {
			msgData, err = c.decryptData(msg.Data)
			if err != nil {
				c.errc <- fmt.Errorf("failed to decrypt data: %w", err)
				continue
			}
		}
		switch msg.Type {
		case v1.CampfireMessage_OFFER:
			c.log.Debug("Decoding offer", "offer", string(msgData))
			var offer webrtc.SessionDescription
			err = json.Unmarshal(msgData, &offer)
			if err != nil {
				c.errc <- fmt.Errorf("failed to unmarshal offer: %w", err)
				continue
			}
			c.offers <- CampfireOffer{
				ID:    msg.Id,
				Ufrag: msg.Lufrag,
				Pwd:   msg.Lpwd,
				SDP:   offer,
			}
		case v1.CampfireMessage_ANSWER:
			c.log.Debug("Decoding answer", "answer", string(msgData))
			var answer webrtc.SessionDescription
			err = json.Unmarshal(msgData, &answer)
			if err != nil {
				c.errc <- fmt.Errorf("failed to unmarshal answer: %w", err)
				continue
			}
			c.answers <- CampfireAnswer{
				ID:    msg.Id,
				Ufrag: msg.Lufrag,
				Pwd:   msg.Lpwd,
				SDP:   answer,
			}
		case v1.CampfireMessage_CANDIDATE:
			c.log.Debug("Decoding candidate", "candidate", string(msgData))
			var candidate webrtc.ICECandidateInit
			err = json.Unmarshal(msgData, &candidate)
			if err != nil {
				c.errc <- fmt.Errorf("failed to unmarshal candidate: %w", err)
				continue
			}
			c.candidates <- CampfireCandidate{
				ID:    msg.Id,
				Ufrag: msg.Lufrag,
				Pwd:   msg.Lpwd,
				Cand:  candidate,
			}
		}
	}
}

func (c *CampfireClient) encryptData(data []byte) []byte {
	nonce := make([]byte, c.cipher.NonceSize())
	out := c.cipher.Seal(nil, nonce, data, nil)
	return out
}

func (c *CampfireClient) decryptData(data []byte) ([]byte, error) {
	nonce := make([]byte, c.cipher.NonceSize())
	plaintext, err := c.cipher.Open(nil, nonce, data, nil)
	if err != nil {
		return nil, errors.New("failed to decrypt data")
	}
	return plaintext, nil
}
