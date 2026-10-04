package audit

import (
	"encoding/json"
	"log"
	"time"
)

type Event struct {
	Time         string   `json:"time"`
	Type         string   `json:"type"`
	RootUserDID  string   `json:"root_user_did,omitempty"`
	CallerDID    string   `json:"caller_did,omitempty"`
	CapabilityID string   `json:"capability_id,omitempty"`
	Allowed      bool     `json:"allowed"`
	Reasons      []string `json:"reasons"`
}
type Sink interface{ Write(Event) }
type JSONLogSink struct{}

func (JSONLogSink) Write(e Event) {
	e.Time = time.Now().UTC().Format(time.RFC3339Nano)
	b, _ := json.Marshal(e)
	log.Printf("%s", b)
}
