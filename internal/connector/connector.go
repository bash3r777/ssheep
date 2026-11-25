// Package connector is the address book and relay.
//
// It is deliberately blind: it verifies that every machine holds the key the
// roster says it holds, then forwards opaque payloads between them. It cannot
// read a command, forge one, or impersonate a member.
package connector

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"sshepard.com/internal/flock"
	"sshepard.com/internal/frame"
	"sshepard.com/internal/netx"
	"sshepard.com/internal/peer"
	"sshepard.com/internal/proto"
)

// Server is a running connector.
type Server struct {
	rosterPath string
	roster     atomic.Pointer[flock.SignedRoster]
	cert       tls.Certificate
	pin        string

	mu    sync.Mutex
	peers map[string]*session
}

type session struct {
	id    string
	name  string
	role  string
	since time.Time
	conn  *frame.Conn
}

// New loads the roster and the connector's certificate, generating the
// certificate on first run.
func New(rosterPath, certPath, keyPath string) (*Server, error) {
	sr, err := flock.LoadSignedRoster(rosterPath)
	if err != nil {
		return nil, err
	}
	if _, err := sr.Verify(); err != nil {
		return nil, err
	}
	cert, err := netx.LoadOrCreateSelfSigned(certPath, keyPath)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, err
	}
	s := &Server{
		rosterPath: rosterPath,
		cert:       cert,
		pin:        netx.Pin(leaf),
		peers:      map[string]*session{},
	}
	s.roster.Store(sr)
	go s.watchRoster()
	return s, nil
}

// Pin reports the connector's fingerprint, which every client pins.
func (s *Server) Pin() string { return s.pin }

// ListenAndServe accepts connections until the listener fails.
func (s *Server) ListenAndServe(addr string) error {
	ln, err := tls.Listen("tcp", addr, netx.ServerConfig(s.cert))
	if err != nil {
		return err
	}
	log.Printf("connector listening on %s", addr)
	log.Printf("connector fingerprint %s", s.pin)
	for {
		nc, err := ln.Accept()
		if err != nil {
			return err
		}
		go s.handle(nc)
	}
}

// watchRoster reloads the roster when the file changes, so revoking a machine
// takes effect without restarting anything.
func (s *Server) watchRoster() {
	var last time.Time
	if fi, err := os.Stat(s.rosterPath); err == nil {
		last = fi.ModTime()
	}
	for range time.Tick(2 * time.Second) {
		fi, err := os.Stat(s.rosterPath)
		if err != nil || !fi.ModTime().After(last) {
			continue
		}
		sr, err := flock.LoadSignedRoster(s.rosterPath)
		if err != nil {
			log.Printf("connector: roster reload failed: %v", err)
			continue
		}
		r, err := sr.Verify()
		if err != nil {
			log.Printf("connector: refusing an unverifiable roster: %v", err)
			continue
		}
		last = fi.ModTime()
		s.roster.Store(sr)
		log.Printf("connector: roster now at version %d (%d members)", r.Version, len(r.Members))
		s.dropUnknown()
	}
}

// dropUnknown disconnects members that are no longer in the roster.
func (s *Server) dropUnknown() {
	sr := s.roster.Load()
	if sr == nil {
		return
	}
	r, err := sr.Verify()
	if err != nil {
		return
	}
	s.mu.Lock()
	var gone []*session
	for id, p := range s.peers {
		if r.Find(id) == nil {
			gone = append(gone, p)
			delete(s.peers, id)
		}
	}
	s.mu.Unlock()
	for _, p := range gone {
		log.Printf("connector: %s is no longer in the roster, dropping", p.name)
		_ = peer.Send(p.conn, proto.Wrap(proto.TypeError, proto.ErrMsg{Message: "you are no longer in the roster"}))
		p.conn.Close()
	}
}

func (s *Server) version() uint64 {
	sr := s.roster.Load()
	if sr == nil {
		return 0
	}
	r, err := sr.Open()
	if err != nil {
		return 0
	}
	return r.Version
}

func (s *Server) add(p *session) {
	s.mu.Lock()
	if old, ok := s.peers[p.id]; ok {
		old.conn.Close()
	}
	s.peers[p.id] = p
	s.mu.Unlock()
}

func (s *Server) remove(p *session) {
	s.mu.Lock()
	if cur, ok := s.peers[p.id]; ok && cur == p {
		delete(s.peers, p.id)
	}
	s.mu.Unlock()
}

// handle runs one connection for its whole life.
func (s *Server) handle(nc net.Conn) {
	defer nc.Close()
	f := frame.New(nc)

	m, err := s.authenticate(f)
	if err != nil {
		_ = peer.Send(f, proto.Wrap(proto.TypeError, proto.ErrMsg{Message: err.Error()}))
		log.Printf("connector: refused %s: %v", nc.RemoteAddr(), err)
		return
	}

	p := &session{id: m.ID, name: m.Name, role: m.Role, since: time.Now(), conn: f}
	s.add(p)
	defer s.remove(p)
	log.Printf("connector: %s (%s) connected from %s", p.name, p.id, nc.RemoteAddr())

	if err := peer.Send(f, proto.Wrap(proto.TypeReady, proto.Ready{Version: s.version()})); err != nil {
		return
	}
	for {
		env, err := peer.Read(f)
		if err != nil {
			log.Printf("connector: %s disconnected", p.name)
			return
		}
		if err := s.dispatch(p, env); err != nil {
			e := proto.Wrap(proto.TypeError, proto.ErrMsg{Message: err.Error()})
			if env.Type == proto.TypeRoute {
				// Point the error at the machine that could not be reached, so
				// the sender learns which target failed instead of waiting.
				e.To = env.To
				if e.To == "" {
					var rt proto.Route
					if env.Decode(&rt) == nil {
						e.To = rt.To
					}
				}
			}
			_ = peer.Send(f, e)
		}
	}
}

// authenticate challenges the peer and checks its signature against the roster.
func (s *Server) authenticate(f *frame.Conn) (*flock.Member, error) {
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	if err := peer.Send(f, proto.Wrap(proto.TypeChallenge, proto.Challenge{Nonce: nonce})); err != nil {
		return nil, err
	}
	env, err := peer.Read(f)
	if err != nil {
		return nil, err
	}
	if env.Type != proto.TypeAuth {
		return nil, fmt.Errorf("expected authentication, got %q", env.Type)
	}
	var a proto.Auth
	if err := env.Decode(&a); err != nil {
		return nil, err
	}
	sr := s.roster.Load()
	if sr == nil {
		return nil, errors.New("connector has no roster")
	}
	r, err := sr.Verify()
	if err != nil {
		return nil, err
	}
	m := r.Find(a.ID)
	if m == nil {
		return nil, errors.New("this machine is not in the roster")
	}
	if len(m.SignKey) != ed25519.PublicKeySize {
		return nil, errors.New("roster entry has a malformed key")
	}
	if !ed25519.Verify(ed25519.PublicKey(m.SignKey), peer.AuthMessage(a.ID, nonce), a.Sig) {
		return nil, errors.New("signature does not verify")
	}
	return m, nil
}

func (s *Server) dispatch(from *session, env *proto.Envelope) error {
	switch env.Type {
	case proto.TypeList:
		return s.sendList(from)
	case proto.TypeRoute:
		return s.forward(from, env)
	case proto.TypeRoster:
		sr := s.roster.Load()
		if sr == nil {
			return errors.New("no roster")
		}
		body, err := json.Marshal(sr)
		if err != nil {
			return err
		}
		return peer.Send(from.conn, &proto.Envelope{Type: proto.TypeRoster, Body: body, To: from.id})
	case proto.TypeRosterPush:
		return s.acceptRoster(from, env)
	default:
		return fmt.Errorf("unknown message type %q", env.Type)
	}
}

// acceptRoster adopts a roster published by a shepherd.
//
// Two things are checked before it is believed: the signature, and that it is
// signed by the same flock key as the roster we already have. Without the second
// check, anyone could push a roster signed by their own key and take the flock.
func (s *Server) acceptRoster(from *session, env *proto.Envelope) error {
	if from.role != flock.RoleShepherd {
		return errors.New("only a shepherd may publish a roster")
	}
	var sr flock.SignedRoster
	if err := json.Unmarshal(env.Body, &sr); err != nil {
		return errors.New("that is not a roster")
	}
	r, err := sr.Verify()
	if err != nil {
		return err
	}
	if cur := s.roster.Load(); cur != nil {
		if cr, err := cur.Verify(); err == nil && !bytes.Equal(cr.FlockKey, r.FlockKey) {
			return errors.New("that roster belongs to a different flock")
		}
	}
	if err := sr.Save(s.rosterPath); err != nil {
		return err
	}
	s.roster.Store(&sr)
	log.Printf("connector: roster published by %s, now at version %d (%d members)", from.name, r.Version, len(r.Members))
	s.dropUnknown()
	return peer.Send(from.conn, proto.Wrap(proto.TypeReady, proto.Ready{Version: r.Version}))
}

func (s *Server) sendList(from *session) error {
	sr := s.roster.Load()
	if sr == nil {
		return errors.New("no roster")
	}
	r, err := sr.Verify()
	if err != nil {
		return err
	}
	s.mu.Lock()
	online := make(map[string]bool, len(s.peers))
	for id := range s.peers {
		online[id] = true
	}
	s.mu.Unlock()

	reply := proto.ListReply{Version: r.Version}
	for _, m := range r.Members {
		reply.Members = append(reply.Members, proto.MemberStatus{
			ID: m.ID, Name: m.Name, Role: m.Role, Online: online[m.ID],
		})
	}
	return peer.Send(from.conn, proto.Wrap(proto.TypeListReply, reply))
}

// forward delivers an opaque payload without looking inside it.
func (s *Server) forward(from *session, env *proto.Envelope) error {
	var rt proto.Route
	if err := env.Decode(&rt); err != nil {
		return err
	}
	if rt.To == from.id {
		return errors.New("cannot route a message to yourself")
	}
	s.mu.Lock()
	dst := s.peers[rt.To]
	s.mu.Unlock()
	if dst == nil {
		return errors.New("that machine is not connected right now")
	}
	payload := rt.Payload
	if len(payload) == 0 {
		payload = json.RawMessage(`null`)
	}
	return peer.Send(dst.conn, proto.Wrap(proto.TypeData, proto.Data{From: from.id, Payload: payload}))
}
