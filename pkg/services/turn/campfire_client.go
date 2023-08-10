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
	"encoding/json"
	"net"
	"strings"
	"time"

	"github.com/pion/webrtc/v3"
)

// CampfireClient represents a client that can communicate with a TURN server
// supporting campfire.
type CampfireClient struct {
	opts       CampfireClientOptions
	conn       *net.UDPConn
	offers     chan CampfireOffer
	answers    chan CampfireAnswer
	candidates chan CampfireCandidate
	errc       chan error
	closec     chan struct{}
}

// CampfireClientOptions represents options for a CampfireClient.
type CampfireClientOptions struct {
	Addr  string
	Ufrag string
	Pwd   string
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
		conn:       conn,
		offers:     make(chan CampfireOffer, 1),
		answers:    make(chan CampfireAnswer, 1),
		candidates: make(chan CampfireCandidate, 1),
		errc:       make(chan error, 1),
		closec:     make(chan struct{}),
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
	msg := campfireMessage{
		LUfrag: c.opts.Ufrag,
		LPwd:   c.opts.Pwd,
		RUfrag: ufrag,
		RPwd:   pwd,
		Type:   campfireMessageAnnounce,
	}
	data, err := msg.encode()
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

// SendOffer sends an offer to the peer with the given ufrag and pwd.
func (c *CampfireClient) SendOffer(ufrag, pwd string, offer webrtc.SessionDescription) error {
	sdp, err := json.Marshal(offer)
	if err != nil {
		return err
	}
	msg := campfireMessage{
		LUfrag: c.opts.Ufrag,
		LPwd:   c.opts.Pwd,
		RUfrag: ufrag,
		RPwd:   pwd,
		Type:   campfireMessageOffer,
		Data:   string(sdp),
	}
	data, err := msg.encode()
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
	msg := campfireMessage{
		LUfrag: c.opts.Ufrag,
		LPwd:   c.opts.Pwd,
		RUfrag: ufrag,
		RPwd:   pwd,
		Type:   campfireMessageAnswer,
		Data:   string(sdp),
	}
	data, err := msg.encode()
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
	msg := campfireMessage{
		LUfrag: c.opts.Ufrag,
		LPwd:   c.opts.Pwd,
		RUfrag: ufrag,
		RPwd:   pwd,
		Type:   campfireMessageICE,
		Data:   string(cand),
	}
	data, err := msg.encode()
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
		data := make([]byte, 1024)
		n, _, err := c.conn.ReadFromUDP(data)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			c.errc <- err
			return
		}
		var msg campfireMessage
		err = msg.decode(data[:n])
		if err != nil {
			c.errc <- err
			return
		}
		switch msg.Type {
		case campfireMessageOffer:
			var offer webrtc.SessionDescription
			err = json.Unmarshal([]byte(msg.Data), &offer)
			if err != nil {
				c.errc <- err
				return
			}
			c.offers <- CampfireOffer{
				Ufrag: msg.LUfrag,
				Pwd:   msg.LPwd,
				SDP:   offer,
			}
		case campfireMessageAnswer:
			var answer webrtc.SessionDescription
			err = json.Unmarshal([]byte(msg.Data), &answer)
			if err != nil {
				c.errc <- err
				return
			}
			c.answers <- CampfireAnswer{
				Ufrag: msg.LUfrag,
				Pwd:   msg.LPwd,
				SDP:   answer,
			}
		case campfireMessageICE:
			var candidate webrtc.ICECandidateInit
			err = json.Unmarshal([]byte(msg.Data), &candidate)
			if err != nil {
				c.errc <- err
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
