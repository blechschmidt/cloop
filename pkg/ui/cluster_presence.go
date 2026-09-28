package ui

// cluster_presence.go: who is looking at a project, across hub members, and
// which of them just edited the same task (Task 20354).
//
// Both used to be answered from one process's socket set. With several
// members, two people on the same project are as likely to be attached to
// different members as to the same one, and the presence bar and the
// conflicting-edit toast would each have shown only the half on their own
// member. Every member now publishes its own half and merges everyone else's.

import (
	"time"

	"github.com/blechschmidt/cloop/pkg/hubcluster"
)

// remotePresenceUsers returns the users other members reported for workDir.
func (s *Server) remotePresenceUsers(workDir string) []presenceUser {
	s.clusterMu.Lock()
	defer s.clusterMu.Unlock()
	var out []presenceUser
	for _, users := range s.remotePresence[workDir] {
		out = append(out, users...)
	}
	return out
}

// publishPresence tells other members who is on workDir here.
func (s *Server) publishPresence(workDir string) {
	n := s.clusterNode()
	if n == nil || workDir == "" {
		return
	}
	n.Publish(busTopicPresence, workDir, map[string]any{"users": s.localPresenceUsers(workDir)})
}

// republishPresence re-announces every room this member has clients in. Sent
// when membership changes, because a member that just joined has heard
// nobody's presence and would otherwise show an empty bar until somebody
// happened to connect or leave.
func (s *Server) republishPresence() {
	if s.clusterNode() == nil {
		return
	}
	s.hubMu.Lock()
	rooms := make([]string, 0, len(s.hubClients))
	for workDir := range s.hubClients {
		rooms = append(rooms, workDir)
	}
	s.hubMu.Unlock()
	for _, workDir := range rooms {
		s.publishPresence(workDir)
	}
}

func (s *Server) onBusPresence(ev hubcluster.Event) {
	if ev.Key == "" {
		return
	}
	var p struct {
		Users []presenceUser `json:"users"`
	}
	if err := ev.Decode(&p); err != nil {
		return
	}
	// Bounded like the local list: a member cannot make this one hold more
	// users per room than a room could have connections.
	if len(p.Users) > maxPresenceUsersPerOrigin {
		p.Users = p.Users[:maxPresenceUsersPerOrigin]
	}
	s.clusterMu.Lock()
	if s.remotePresence == nil {
		s.remotePresence = map[string]map[string][]presenceUser{}
	}
	byOrigin := s.remotePresence[ev.Key]
	if byOrigin == nil {
		byOrigin = map[string][]presenceUser{}
		s.remotePresence[ev.Key] = byOrigin
	}
	if len(p.Users) == 0 {
		delete(byOrigin, ev.Origin)
		if len(byOrigin) == 0 {
			delete(s.remotePresence, ev.Key)
		}
	} else {
		byOrigin[ev.Origin] = p.Users
	}
	s.clusterMu.Unlock()
	s.deliverPresence(ev.Key)
}

// maxPresenceUsersPerOrigin caps what one member may report for one room.
const maxPresenceUsersPerOrigin = 256

// busEdit is one task edit, relayed for conflict detection.
type busEdit struct {
	TaskID   int      `json:"task_id"`
	Fields   []string `json:"fields"`
	ClientID string   `json:"client_id"`
	At       int64    `json:"at"`
}

// publishEdit tells other members that clientID edited these fields, so an
// edit of the same field arriving at them within the conflict window is
// flagged the way it would be here.
func (s *Server) publishEdit(workDir, clientID string, taskID int, fields []string) {
	n := s.clusterNode()
	if n == nil || !n.HasPeers() {
		return
	}
	n.Publish(busTopicEdit, workDir, busEdit{
		TaskID: taskID, Fields: fields, ClientID: clientID, At: time.Now().UnixMilli(),
	})
}

func (s *Server) onBusEdit(ev hubcluster.Event) {
	if ev.Key == "" {
		return
	}
	var e busEdit
	if err := ev.Decode(&e); err != nil || len(e.Fields) == 0 {
		return
	}
	s.recordRemoteEdit(ev.Key, e.ClientID, e.TaskID, e.Fields, time.UnixMilli(e.At))
}
