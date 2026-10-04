package main

import (
	"github.com/example/decentralized-agent-identity-capability-runtime/internal/audit"
	"github.com/example/decentralized-agent-identity-capability-runtime/internal/did"
	"github.com/example/decentralized-agent-identity-capability-runtime/internal/httpapi"
	"github.com/example/decentralized-agent-identity-capability-runtime/internal/policy"
	"github.com/example/decentralized-agent-identity-capability-runtime/internal/store"
	"log"
	"net/http"
	"os"
	"time"
)

func main() {
	resolver := did.NewMemoryResolver()
	revocations := store.NewMemoryRevocations()
	engine := &policy.Engine{Resolver: resolver, Revocations: revocations, Audit: audit.JSONLogSink{}, MaxDepth: 8}
	s := &httpapi.Server{Engine: engine, Resolver: resolver, Revocations: revocations, AdminToken: os.Getenv("ADMIN_TOKEN")}
	addr := os.Getenv("LISTEN_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	srv := &http.Server{Addr: addr, Handler: s.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 60 * time.Second}
	log.Printf("agent capability runtime listening on %s", addr)
	log.Fatal(srv.ListenAndServe())
}
