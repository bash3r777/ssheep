// Package connector is the address book and relay.
//
// It is deliberately blind: it verifies that every machine holds the key the
// roster says it holds, then forwards opaque payloads between machines in the
// same flock. It cannot read a command, forge one, or impersonate a member.
//
// A connector can serve one flock or many. When it is public it learns a flock
// from the flock itself: a member presents the signed roster and a proof that it
// belongs to it, and that is the whole enrolment procedure. No signup, no
// registry, nothing to be talked into trusting.
package connector

import (
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
	"sort"
	"sync"
	"time"

	"ssheep.xyz/internal/flock"
	"ssheep.xyz/internal/frame"
	"ssheep.xyz/internal/netx"
	"ssheep.xyz/internal/peer"
	"ssheep.xyz/internal/proto"
)

// offerTTL is how long a machine's offer to be a relay is worth keeping. Long
// enough for someone to start a connector and then run a command on the master;
// short enough that stale addresses do not linger.
const offerTTL = 24 * time.Hour

// Config describes how a connector should behave.
type Config struct {
	// RosterPaths are the flocks to serve from startup, one file each. A public
	// relay can start with none and learn flocks as they walk up.
	RosterPaths []string

	CertPath string
	KeyPath  string

	// Public means: accept flocks this connector has never seen, on the word of
	// a roster they sign themselves. Off by default, because serving strangers
	// is a decision an operator should have to make out loud.
	Public bool

	// Limits, so one flock or one stranger cannot eat a donated relay.
	MaxFlocks  int // 0 = no limit
	MaxConns   int // 0 = no limit
	MaxMembers int // 0 = no limit
}

// Server is a running connector.
type Server struct {
	cfg  Config
	cert tls.Certificate
	pin  string

	mu     sync.Mutex
	flocks map[string]*flockState
	conns  int
}

// flockState is one flock's slice of a connector. Peers are held per flock, so
// routing can never cross from one flock into another.
type flockState struct {
	id string

	mu     sync.Mutex
	sr     *flock.SignedRoster
	ver    uint64
	peers  map[string]*session
	offers map[string]proto.Offer
}

type session struct {
	id    string
	name  string
	role  string
	addr  string // what this connection looks like from here
	since time.Time
	conn  *frame.Conn
}

// New loads the connector's certificate, generating it on first run, and takes
// on every flock it was pointed at.
func New(cfg Config) (*Server, error) {
	cert, err := netx.LoadOrCreateSelfSigned(cfg.CertPath, cfg.KeyPath)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, err
	}
	s := &Server{cfg: cfg, cert: cert, pin: netx.Pin(leaf), flocks: map[string]*flockState{}}

	for _, path := range cfg.RosterPaths {
		sr, err := flock.LoadSignedRoster(path)
		switch {
		case err == nil:
			st, _, err := s.adopt(sr)
			if err != nil {
				return nil, err
			}
			r, _, _ := st.roster()
			log.Printf("connector: serving flock %s %q from %s (%d members)", st.id, r.Name, path, len(r.Members))
			go s.watchRoster(path)
		case os.IsNotExist(err):
			// Nothing yet. A public connector can learn flocks later.
		default:
			return nil, err
		}
	}
	return s, nil
}

// Pin reports the connector's fingerprint, which every client pins.
func (s *Server) Pin() string { return s.pin }

// ListenAndServe accepts connections until the listener fails.
func (s *Server) ListenAndServe(addr string) error {
	ln, err := s.Listen(addr)
	if err != nil {
		return err
	}
	log.Printf("connector listening on %s", addr)
	if s.cfg.Public {
		log.Printf("connector is public: it will serve any flock that can prove itself")
	}
	return s.Serve(ln)
}

// Listen binds a TLS listener, so an embedder (or a test) can choose the address.
func (s *Server) Listen(addr string) (net.Listener, error) {
	ln, err := tls.Listen("tcp", addr, netx.ServerConfig(s.cert))
	if err != nil {
		return nil, err
	}
	log.Printf("connector fingerprint %s", s.pin)
	return ln, nil
}

// Serve accepts connections on ln until it fails.
func (s *Server) Serve(ln net.Listener) error {
	for {
		nc, err := ln.Accept()
		if err != nil {
			return err
		}
		go s.handle(nc)
	}
}

// watchRoster reloads one roster file when it changes, so an operator running a
// private connector can edit a flock without restarting anything.
func (s *Server) watchRoster(path string) {
	var last time.Time
	if fi, err := os.Stat(path); err == nil {
		last = fi.ModTime()
	}
	for range time.Tick(2 * time.Second) {
		fi, err := os.Stat(path)
		if err != nil || !fi.ModTime().After(last) {
			continue
		}
		last = fi.ModTime()
		sr, err := flock.LoadSignedRoster(path)
		if err != nil {
			log.Printf("connector: roster reload failed: %v", err)
			continue
		}
		if _, changed, err := s.adopt(sr); err != nil {
			log.Printf("connector: refusing that roster: %v", err)
		} else if changed {
			log.Printf("connector: reloaded %s", path)
		}
	}
}

// adopt stores a roster if it is newer than what we already hold for that flock.
//
// Refusing older versions is what stops a revoked machine from replaying the
// roster that still listed it.
func (s *Server) adopt(sr *flock.SignedRoster) (*flockState, bool, error) {
	r, err := sr.Verify()
	if err != nil {
		return nil, false, err
	}
	id := flock.FlockID(r.FlockKey)
	if s.cfg.MaxMembers > 0 && len(r.Members) > s.cfg.MaxMembers {
		return nil, false, fmt.Errorf("this flock has %d members and this connector accepts at most %d", len(r.Members), s.cfg.MaxMembers)
	}

	s.mu.Lock()
	st := s.flocks[id]
	if st == nil {
		if s.cfg.MaxFlocks > 0 && len(s.flocks) >= s.cfg.MaxFlocks {
			s.mu.Unlock()
			return nil, false, errors.New("this connector is already serving as many flocks as it will take")
		}
		st = &flockState{id: id, peers: map[string]*session{}}
		s.flocks[id] = st
	}
	s.mu.Unlock()

	gone, changed := st.setRoster(sr, r)
	for _, p := range gone {
		log.Printf("connector: %s is no longer in flock %s, dropping", p.name, id)
		_ = peer.Send(p.conn, proto.Wrap(proto.TypeError, proto.ErrMsg{Message: "you are no longer in the roster"}))
		_ = p.conn.Close()
	}
	if changed {
		st.announce(sr)
	}
	return st, changed, nil
}

// announce hands the new roster to everyone in the flock.
//
// Without this a machine that has been connected for weeks only ever learns
// about a change when it happens to reconnect, so adding a connector would do
// nothing for it until a restart.
func (st *flockState) announce(sr *flock.SignedRoster) {
	body, err := json.Marshal(sr)
	if err != nil {
		return
	}
	env := &proto.Envelope{Type: proto.TypeRoster, Body: body}
	for _, p := range st.peerList() {
		if err := peer.Send(p.conn, env); err != nil {
			log.Printf("connector: could not tell %s about the new roster: %v", p.name, err)
		}
	}
}

func (st *flockState) peerList() []*session {
	st.mu.Lock()
	defer st.mu.Unlock()
	out := make([]*session, 0, len(st.peers))
	for _, p := range st.peers {
		out = append(out, p)
	}
	return out
}

func (st *flockState) setRoster(sr *flock.SignedRoster, r flock.Roster) ([]*session, bool) {
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.sr != nil && r.Version <= st.ver {
		return nil, false
	}
	st.sr, st.ver = sr, r.Version
	var gone []*session
	for id, p := range st.peers {
		if r.Find(id) == nil {
			gone = append(gone, p)
			delete(st.peers, id)
		}
	}
	return gone, true
}

func (st *flockState) roster() (flock.Roster, *flock.SignedRoster, error) {
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.sr == nil {
		return flock.Roster{}, nil, errors.New("this flock has no roster yet")
	}
	r, err := st.sr.Open()
	return r, st.sr, err
}

func (st *flockState) version() uint64 {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.ver
}

func (st *flockState) addPeer(p *session) {
	st.mu.Lock()
	if old := st.peers[p.id]; old != nil {
		old.conn.Close()
	}
	st.peers[p.id] = p
	st.mu.Unlock()
}

func (st *flockState) removePeer(p *session) {
	st.mu.Lock()
	if cur := st.peers[p.id]; cur == p {
		delete(st.peers, p.id)
	}
	st.mu.Unlock()
}

func (st *flockState) peer(id string) *session {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.peers[id]
}

func (st *flockState) online() map[string]bool {
	st.mu.Lock()
	defer st.mu.Unlock()
	on := make(map[string]bool, len(st.peers))
	for id := range st.peers {
		on[id] = true
	}
	return on
}

func (s *Server) takeConn() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cfg.MaxConns > 0 && s.conns >= s.cfg.MaxConns {
		return false
	}
	s.conns++
	return true
}

func (s *Server) dropConn() {
	s.mu.Lock()
	s.conns--
	s.mu.Unlock()
}

// handle runs one connection for its whole life.
func (s *Server) handle(nc net.Conn) {
	defer nc.Close()
	if !s.takeConn() {
		f := frame.New(nc)
		_ = peer.Send(f, proto.Wrap(proto.TypeError, proto.ErrMsg{Message: "this connector is full"}))
		return
	}
	defer s.dropConn()

	f := frame.New(nc)
	st, m, err := s.handshake(f)
	if err != nil {
		_ = peer.Send(f, proto.Wrap(proto.TypeError, proto.ErrMsg{Message: err.Error()}))
		log.Printf("connector: refused %s: %v", nc.RemoteAddr(), err)
		return
	}

	p := &session{id: m.ID, name: m.Name, role: m.Role, addr: nc.RemoteAddr().String(), since: time.Now(), conn: f}
	st.addPeer(p)
	defer st.removePeer(p)
	log.Printf("connector: %s (%s) connected from %s [flock %s]", p.name, p.id, nc.RemoteAddr(), st.id)

	if err := peer.Send(f, proto.Wrap(proto.TypeReady, proto.Ready{Version: st.version(), YouAre: p.addr})); err != nil {
		return
	}
	for {
		env, err := peer.Read(f)
		if err != nil {
			log.Printf("connector: %s disconnected", p.name)
			return
		}
		if err := s.dispatch(st, p, env); err != nil {
			e := proto.Wrap(proto.TypeError, proto.ErrMsg{Message: err.Error()})
			if env.Type == proto.TypeRoute {
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

// handshake proves who is on the other end, and takes on the flock it offers.
func (s *Server) handshake(f *frame.Conn) (*flockState, *flock.Member, error) {
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, err
	}
	if err := peer.Send(f, proto.Wrap(proto.TypeChallenge, proto.Challenge{Nonce: nonce})); err != nil {
		return nil, nil, err
	}

	env, err := peer.Read(f)
	if err != nil {
		return nil, nil, err
	}
	if env.Type != proto.TypeAuth {
		return nil, nil, fmt.Errorf("expected authentication, got %q", env.Type)
	}
	var a proto.Auth
	if err := env.Decode(&a); err != nil {
		return nil, nil, err
	}

	st, err := s.learn(a)
	if err != nil {
		return nil, nil, err
	}

	r, _, err := st.roster()
	if err != nil {
		return nil, nil, err
	}
	m := r.Find(a.ID)
	if m == nil {
		return nil, nil, errors.New("this machine is not in the roster")
	}
	if len(m.SignKey) != ed25519.PublicKeySize {
		return nil, nil, errors.New("that roster entry has a malformed key")
	}
	if !ed25519.Verify(ed25519.PublicKey(m.SignKey), peer.AuthMessage(a.Flock, a.ID, nonce), a.Sig) {
		return nil, nil, errors.New("signature does not verify")
	}
	return st, m, nil
}

// learn takes on the roster a machine offered with its authentication.
//
// This is the whole enrolment procedure for a public relay: the roster is signed
// by the flock key, so the relay can check it while trusting nothing in advance.
// A private relay still only serves what its operator gave it.
//
// Adopting before checking the signature matters: a machine added in version 3
// cannot authenticate against a relay still holding version 1, so the relay has
// to accept the newer roster first.
func (s *Server) learn(a proto.Auth) (*flockState, error) {
	s.mu.Lock()
	st := s.flocks[a.Flock]
	s.mu.Unlock()

	if len(a.Roster) == 0 {
		if st == nil {
			return nil, errors.New("this connector does not know that flock")
		}
		return st, nil
	}

	var sr flock.SignedRoster
	if err := json.Unmarshal(a.Roster, &sr); err != nil {
		return nil, errors.New("that is not a roster")
	}
	r, err := sr.Verify()
	if err != nil {
		return nil, err
	}
	// The flock's id is derived from its key, so a roster cannot claim an id it
	// cannot sign for.
	if flock.FlockID(r.FlockKey) != a.Flock {
		return nil, errors.New("that roster does not belong to the flock it claims")
	}
	if st == nil && !s.cfg.Public {
		return nil, errors.New("this connector does not serve that flock")
	}

	known := st != nil
	st, changed, err := s.adopt(&sr)
	if err != nil {
		return nil, err
	}
	switch {
	case changed && !known:
		log.Printf("connector: learnt flock %s %q from %s, version %d, %d members", st.id, r.Name, a.ID, r.Version, len(r.Members))
	case changed:
		log.Printf("connector: %s brought flock %s to version %d (%d members)", a.ID, st.id, r.Version, len(r.Members))
	}
	return st, nil
}

func (s *Server) dispatch(st *flockState, from *session, env *proto.Envelope) error {
	switch env.Type {
	case proto.TypeList:
		return s.sendList(st, from)
	case proto.TypeRoute:
		return s.forward(st, from, env)
	case proto.TypeRoster:
		_, sr, err := st.roster()
		if err != nil {
			return err
		}
		body, err := json.Marshal(sr)
		if err != nil {
			return err
		}
		return peer.Send(from.conn, &proto.Envelope{Type: proto.TypeRoster, Body: body, To: from.id})
	case proto.TypeOffer:
		return s.acceptOffer(st, from, env)
	default:
		return fmt.Errorf("unknown message type %q", env.Type)
	}
}

// acceptOffer files a machine's offer to be a relay.
//
// The relay only keeps it. Whether the offer is *believed* is the master's
// decision: it checks the signature against the roster and then dials the
// address itself. Keeping that out of the relay means a relay cannot promote
// itself into the flock.
func (s *Server) acceptOffer(st *flockState, from *session, env *proto.Envelope) error {
	var o proto.Offer
	if err := env.Decode(&o); err != nil {
		return err
	}
	if o.ID != from.id {
		return errors.New("an offer has to be made by the machine sending it")
	}
	host, port, err := net.SplitHostPort(o.Addr)
	if err != nil || host == "" || port == "" {
		return errors.New("an offer needs an address in host:port form")
	}
	if len(o.Pin) != 64 {
		return errors.New("an offer needs a certificate fingerprint")
	}
	o.Name = from.name
	o.At = time.Now().UTC()
	st.setOffer(o)
	log.Printf("connector: %s offers itself as a connector at %s", from.name, o.Addr)
	return peer.Send(from.conn, proto.Wrap(proto.TypeReady, proto.Ready{Version: st.version()}))
}

func (s *Server) sendList(st *flockState, from *session) error {
	r, _, err := st.roster()
	if err != nil {
		return err
	}
	online := st.online()
	reply := proto.ListReply{Version: r.Version, Flock: r.ID(), Name: r.Name}
	for _, m := range r.Members {
		reply.Members = append(reply.Members, proto.MemberStatus{
			ID: m.ID, Name: m.Name, Role: m.Role, Online: online[m.ID],
		})
	}
	// Offers that have already been taken up are no longer interesting.
	taken := make(map[string]bool, len(r.Connectors))
	for _, c := range r.Connectors {
		taken[c.Addr] = true
	}
	for _, o := range st.currentOffers() {
		if !taken[o.Addr] {
			reply.Offers = append(reply.Offers, o)
		}
	}
	return peer.Send(from.conn, proto.Wrap(proto.TypeListReply, reply))
}

// setOffer keeps a machine's offer, replacing any earlier one for the same
// address.
//
// One machine may offer several addresses -- a global IPv6 address, a forwarded
// port, its address on the local network -- because only the master can tell
// which of them the flock can actually reach. So all of them have to survive to
// the master, which is why the key is the machine *and* the address.
func (st *flockState) setOffer(o proto.Offer) {
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.offers == nil {
		st.offers = map[string]proto.Offer{}
	}
	st.offers[o.ID+"|"+o.Addr] = o
}

// currentOffers returns the offers that have not gone stale.
func (st *flockState) currentOffers() []proto.Offer {
	st.mu.Lock()
	defer st.mu.Unlock()
	var out []proto.Offer
	for k, o := range st.offers {
		if time.Since(o.At) > offerTTL {
			delete(st.offers, k)
			continue
		}
		out = append(out, o)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].At.Before(out[j].At) })
	return out
}

// forward delivers an opaque payload without looking inside it.
//
// The target is looked up only within the sender's own flock, so one flock can
// never route into another even if a node id collides.
func (s *Server) forward(st *flockState, from *session, env *proto.Envelope) error {
	var rt proto.Route
	if err := env.Decode(&rt); err != nil {
		return err
	}
	if rt.To == from.id {
		return errors.New("cannot route a message to yourself")
	}
	dst := st.peer(rt.To)
	if dst == nil {
		return errors.New("that machine is not connected right now")
	}
	payload := rt.Payload
	if len(payload) == 0 {
		payload = json.RawMessage(`null`)
	}
	return peer.Send(dst.conn, proto.Wrap(proto.TypeData, proto.Data{From: from.id, Payload: payload}))
}
