package httpapi

import (
	"encoding/json"
	"github.com/example/decentralized-agent-identity-capability-runtime/internal/capability"
	"github.com/example/decentralized-agent-identity-capability-runtime/internal/did"
	"github.com/example/decentralized-agent-identity-capability-runtime/internal/policy"
	"github.com/example/decentralized-agent-identity-capability-runtime/internal/store"
	"net/http"
	"strings"
)

type Server struct {
	Engine      *policy.Engine
	Resolver    *did.MemoryResolver
	Revocations *store.MemoryRevocations
	AdminToken  string
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { json.NewEncoder(w).Encode(map[string]any{"ok": true}) })
	mux.HandleFunc("POST /v1/verify", s.verify)
	mux.HandleFunc("POST /v1/admin/dids", s.adminDID)
	mux.HandleFunc("POST /v1/admin/revocations/", s.revoke)
	return securityHeaders(limitBody(mux))
}
func (s *Server) verify(w http.ResponseWriter, r *http.Request) {
	var req capability.VerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", 400)
		return
	}
	writeJSON(w, s.Engine.Verify(req))
}
func (s *Server) adminDID(w http.ResponseWriter, r *http.Request) {
	if !s.admin(r) {
		http.Error(w, "unauthorized", 401)
		return
	}
	var d did.Document
	if json.NewDecoder(r.Body).Decode(&d) != nil || d.ID == "" {
		http.Error(w, "invalid document", 400)
		return
	}
	s.Resolver.Put(d)
	writeJSON(w, map[string]any{"stored": d.ID})
}
func (s *Server) revoke(w http.ResponseWriter, r *http.Request) {
	if !s.admin(r) {
		http.Error(w, "unauthorized", 401)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/v1/admin/revocations/")
	if id == "" {
		http.Error(w, "missing id", 400)
		return
	}
	s.Revocations.Revoke(id)
	writeJSON(w, map[string]any{"revoked": id})
}
func (s *Server) admin(r *http.Request) bool {
	return s.AdminToken != "" && r.Header.Get("Authorization") == "Bearer "+s.AdminToken
}
func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}
func limitBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		next.ServeHTTP(w, r)
	})
}
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}
