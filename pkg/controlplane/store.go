package controlplane

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/parkiyong/agentbox/pkg/protocol"
	"github.com/parkiyong/agentbox/pkg/sandbox"
)

// Store provides durable storage for Blueprints, Sessions, Warm Workspace Snapshots,
// and an append-only Event Log with live pub/sub fan-out for SSE streams and webhooks.
type Store struct {
	dataDir string

	mu          sync.RWMutex
	blueprints  map[string]*protocol.Blueprint // key: orgID + ":" + name
	sessions    map[string]*protocol.Session   // key: sessionID
	events      map[string][]protocol.Event    // key: sessionID
	subscribers map[string]map[chan protocol.Event]struct{}
	snapshots   map[string]*sandbox.SnapshotRef // key: workspaceID
	seqCounter  map[string]int64
}

func NewStore(dataDir string) (*Store, error) {
	s := &Store{
		dataDir:     dataDir,
		blueprints:  make(map[string]*protocol.Blueprint),
		sessions:    make(map[string]*protocol.Session),
		events:      make(map[string][]protocol.Event),
		subscribers: make(map[string]map[chan protocol.Event]struct{}),
		snapshots:   make(map[string]*sandbox.SnapshotRef),
		seqCounter:  make(map[string]int64),
	}
	if dataDir != "" {
		if err := os.MkdirAll(filepath.Join(dataDir, "events"), 0o755); err != nil {
			return nil, err
		}
		if err := s.loadPersistedEvents(); err != nil {
			return nil, err
		}
	}
	return s, nil
}

func (s *Store) loadPersistedEvents() error {
	evDir := filepath.Join(s.dataDir, "events")
	entries, err := os.ReadDir(evDir)
	if err != nil {
		return nil
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".jsonl") {
			continue
		}
		sessionID := strings.TrimSuffix(e.Name(), ".jsonl")
		f, err := os.Open(filepath.Join(evDir, e.Name()))
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(f)
		scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
		for scanner.Scan() {
			var evt protocol.Event
			if json.Unmarshal(scanner.Bytes(), &evt) == nil {
				s.events[sessionID] = append(s.events[sessionID], evt)
				if evt.Seq > s.seqCounter[sessionID] {
					s.seqCounter[sessionID] = evt.Seq
				}
			}
		}
		f.Close()
	}
	return nil
}

// --- Blueprints ---

func (s *Store) PutBlueprint(orgID string, bp *protocol.Blueprint) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *bp
	s.blueprints[orgID+":"+bp.Metadata.Name] = &cp
}

func (s *Store) GetBlueprint(orgID, name string) (*protocol.Blueprint, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	bp, ok := s.blueprints[orgID+":"+name]
	if !ok {
		return nil, false
	}
	cp := *bp
	return &cp, true
}

func (s *Store) ListBlueprints(orgID string) []*protocol.Blueprint {
	s.mu.RLock()
	defer s.mu.RUnlock()
	prefix := orgID + ":"
	var out []*protocol.Blueprint
	for k, bp := range s.blueprints {
		if strings.HasPrefix(k, prefix) {
			cp := *bp
			out = append(out, &cp)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Metadata.Name < out[j].Metadata.Name })
	return out
}

// --- Sessions ---

func (s *Store) PutSession(sess *protocol.Session) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *sess
	s.sessions[sess.ID] = &cp
}

func (s *Store) GetSession(sessionID string) (*protocol.Session, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sess, ok := s.sessions[sessionID]
	if !ok {
		return nil, false
	}
	cp := *sess
	if sess.PendingApproval != nil {
		ap := *sess.PendingApproval
		cp.PendingApproval = &ap
	}
	return &cp, true
}

func (s *Store) UpdateSession(sessionID string, fn func(*protocol.Session) error) (*protocol.Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[sessionID]
	if !ok {
		return nil, fmt.Errorf("session %q not found", sessionID)
	}
	if err := fn(sess); err != nil {
		return nil, err
	}
	cp := *sess
	return &cp, nil
}

func (s *Store) ListSessions(orgID, customerID string) []*protocol.Session {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []*protocol.Session
	for _, sess := range s.sessions {
		if orgID != "" && sess.OrgID != orgID {
			continue
		}
		if customerID != "" && sess.CustomerID != customerID {
			continue
		}
		cp := *sess
		out = append(out, &cp)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out
}

// --- Snapshots ---

func (s *Store) PutWorkspaceSnapshot(workspaceID string, ref *sandbox.SnapshotRef) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *ref
	s.snapshots[workspaceID] = &cp
}

func (s *Store) GetWorkspaceSnapshot(workspaceID string) (*sandbox.SnapshotRef, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ref, ok := s.snapshots[workspaceID]
	if !ok {
		return nil, false
	}
	cp := *ref
	return &cp, true
}

// --- Durable Append-Only Event Log & SSE Pub/Sub ---

func (s *Store) AppendEvent(evt protocol.Event) protocol.Event {
	s.mu.Lock()
	s.seqCounter[evt.SessionID]++
	evt.Seq = s.seqCounter[evt.SessionID]
	if evt.ID == "" {
		evt.ID = protocol.NewID("evt_")
	}
	s.events[evt.SessionID] = append(s.events[evt.SessionID], evt)

	// Persist durably as JSONL when dataDir is enabled.
	if s.dataDir != "" {
		path := filepath.Join(s.dataDir, "events", evt.SessionID+".jsonl")
		if f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644); err == nil {
			if b, err := json.Marshal(evt); err == nil {
				_, _ = f.Write(append(b, '\n'))
			}
			f.Close()
		}
	}

	// Copy subscriber list to fan out without blocking writers.
	subs := make([]chan protocol.Event, 0, len(s.subscribers[evt.SessionID]))
	for ch := range s.subscribers[evt.SessionID] {
		subs = append(subs, ch)
	}
	s.mu.Unlock()

	for _, ch := range subs {
		select {
		case ch <- evt:
		default:
		}
	}
	return evt
}

// ListEventsAfter returns all events for sessionID after lastEventID (which may be an event ID
// like "evt_..." or a numeric sequence string like "42").
func (s *Store) ListEventsAfter(sessionID, lastEventID string) []protocol.Event {
	s.mu.RLock()
	defer s.mu.RUnlock()
	all := s.events[sessionID]
	if len(all) == 0 {
		return nil
	}
	if strings.TrimSpace(lastEventID) == "" {
		cp := make([]protocol.Event, len(all))
		copy(cp, all)
		return cp
	}

	// Support numeric seq IDs as well as evt_ IDs.
	if seqNum, err := strconv.ParseInt(lastEventID, 10, 64); err == nil {
		var out []protocol.Event
		for _, e := range all {
			if e.Seq > seqNum {
				out = append(out, e)
			}
		}
		return out
	}

	startIdx := 0
	for i, e := range all {
		if e.ID == lastEventID {
			startIdx = i + 1
			break
		}
	}
	if startIdx >= len(all) {
		return nil
	}
	cp := make([]protocol.Event, len(all)-startIdx)
	copy(cp, all[startIdx:])
	return cp
}

// Subscribe registers a live event stream channel for sessionID, returning replay events
// after lastEventID, the live channel, and an unsubscribe cleanup func.
func (s *Store) Subscribe(sessionID, lastEventID string) ([]protocol.Event, <-chan protocol.Event, func()) {
	ch := make(chan protocol.Event, 128)
	s.mu.Lock()
	if s.subscribers[sessionID] == nil {
		s.subscribers[sessionID] = make(map[chan protocol.Event]struct{})
	}
	s.subscribers[sessionID][ch] = struct{}{}
	s.mu.Unlock()

	replay := s.ListEventsAfter(sessionID, lastEventID)
	unsub := func() {
		s.mu.Lock()
		if subs, ok := s.subscribers[sessionID]; ok {
			delete(subs, ch)
		}
		s.mu.Unlock()
	}
	return replay, ch, unsub
}
