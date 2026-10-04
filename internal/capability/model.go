package capability

import "time"

type Scope struct {
	Resource  string   `json:"resource"`
	Actions   []string `json:"actions"`
	Audience  string   `json:"audience"`
	MaxCalls  int      `json:"max_calls"`
	NotBefore int64    `json:"not_before,omitempty"`
	ExpiresAt int64    `json:"expires_at"`
}

type Token struct {
	ID          string `json:"id"`
	IssuerDID   string `json:"issuer_did"`
	SubjectDID  string `json:"subject_did"`
	ParentID    string `json:"parent_id,omitempty"`
	RootUserDID string `json:"root_user_did"`
	Depth       int    `json:"depth"`
	Scope       Scope  `json:"scope"`
	IssuedAt    int64  `json:"issued_at"`
	Nonce       string `json:"nonce"`
	Signature   string `json:"signature"`
}

type VerifyRequest struct {
	Chain     []Token `json:"chain"`
	CallerDID string  `json:"caller_did"`
	Tool      string  `json:"tool"`
	Resource  string  `json:"resource"`
	Action    string  `json:"action"`
	Now       int64   `json:"now,omitempty"`
}

type Decision struct {
	Allowed      bool     `json:"allowed"`
	ReasonCodes  []string `json:"reason_codes"`
	RootUserDID  string   `json:"root_user_did,omitempty"`
	EffectiveDID string   `json:"effective_did,omitempty"`
	CapabilityID string   `json:"capability_id,omitempty"`
	ChainDepth   int      `json:"chain_depth"`
}

func Now() int64 { return time.Now().Unix() }
