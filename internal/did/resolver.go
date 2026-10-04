package did

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"strings"
	"sync"
)

type Document struct {
	ID        string `json:"id"`
	PublicKey string `json:"public_key"`
	Revoked   bool   `json:"revoked"`
}

type Resolver interface {
	Resolve(string) (Document, error)
}

type MemoryResolver struct {
	mu   sync.RWMutex
	docs map[string]Document
}

func NewMemoryResolver() *MemoryResolver {
	return &MemoryResolver{docs: map[string]Document{}}
}

func (r *MemoryResolver) Put(d Document) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.docs[d.ID] = d
}

func (r *MemoryResolver) Resolve(id string) (Document, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	d, ok := r.docs[id]
	if !ok {
		return Document{}, errors.New("did not found")
	}
	if d.Revoked {
		return Document{}, errors.New("did revoked")
	}
	return d, nil
}

func ParseEd25519PublicKey(d Document) (ed25519.PublicKey, error) {
	if !strings.HasPrefix(d.ID, "did:agent:") && !strings.HasPrefix(d.ID, "did:key:") {
		return nil, errors.New("unsupported did method")
	}
	b, err := base64.RawURLEncoding.DecodeString(d.PublicKey)
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil, errors.New("invalid ed25519 public key")
	}
	return ed25519.PublicKey(b), nil
}
