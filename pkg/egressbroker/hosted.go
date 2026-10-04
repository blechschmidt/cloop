package egressbroker

import "time"

// HostedStatusKind is the hub_owners kind under which every hub process
// records the egress proxy it hosts (Task 20378), one row per process, so
// that `cloop hub doctor` — another process, possibly on another machine —
// can say where each hub's proxy listens, or why it does not.
const HostedStatusKind = "egress_proxy"

// HostedStatus is that row's meta: what one hub process did with
// executors.egress.
type HostedStatus struct {
	// Enabled is executors.egress.enabled as the hub read it.
	Enabled bool `json:"enabled"`
	// Listening is the address the proxy is bound to.
	Listening string `json:"listening,omitempty"`
	// Advertised is the address sandboxes are pointed at when no route of
	// their own applies: executors.egress.advertise_addr with the bound port,
	// or the bound address.
	Advertised string `json:"advertised,omitempty"`
	// Error says why an enabled proxy is not running — a listen address that
	// would not bind, a database that would not open.
	Error string `json:"error,omitempty"`
	// HubPort, Hostname, PID and BootID identify the hub process, so a reader
	// can tell a live hub's row from one a crashed hub left behind.
	HubPort   int       `json:"hub_port,omitempty"`
	Hostname  string    `json:"hostname,omitempty"`
	PID       int       `json:"pid,omitempty"`
	BootID    string    `json:"boot_id,omitempty"`
	UpdatedAt time.Time `json:"updated_at"`
}
