package main

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	proto "RelayToGo/protocol"
)

//go:embed ui.html
var uiHTML []byte

type tunnelView struct {
	proto.Mapping
	In      uint64 `json:"in"`
	Out     uint64 `json:"out"`
	Clients int    `json:"clients"`
}

func (a *relayAgent) serveUI(address string) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/status", a.statusAPI)
	mux.HandleFunc("/api/tunnels", a.tunnelsAPI)
	mux.HandleFunc("/api/tunnels/", a.tunnelAPI)
	mux.HandleFunc("/", a.uiPage)
	log.Printf("agent management UI: http://%s", address)
	if err := http.ListenAndServe(address, mux); err != nil {
		log.Printf("agent management UI stopped: %v", err)
	}
}

func (a *relayAgent) statusAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"relay_public_addr": a.relayPublicAddr})
}

func (a *relayAgent) tunnelsAPI(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, a.tunnelViews())
	case http.MethodPost:
		var tunnel proto.Mapping
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&tunnel); err != nil {
			writeAPIError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
			return
		}
		if err := validateTunnel(&tunnel); err != nil {
			writeAPIError(w, http.StatusBadRequest, err.Error())
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		result, err := a.requestTunnel(ctx, proto.Message{Type: proto.MsgTunnelCreate, Tunnel: &tunnel})
		if err != nil {
			writeAPIError(w, http.StatusConflict, err.Error())
			return
		}
		writeJSON(w, http.StatusCreated, result.Tunnel)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (a *relayAgent) tunnelAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/tunnels/")
	if id == "" || strings.Contains(id, "/") {
		writeAPIError(w, http.StatusBadRequest, "invalid tunnel ID")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	if _, err := a.requestTunnel(ctx, proto.Message{Type: proto.MsgTunnelDelete, TunnelID: id}); err != nil {
		writeAPIError(w, http.StatusConflict, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *relayAgent) tunnelViews() []tunnelView {
	a.mu.Lock()
	defer a.mu.Unlock()
	views := make([]tunnelView, 0, len(a.tunnels))
	for _, tunnel := range a.tunnels {
		stats := a.stats[tunnelKey(tunnel.Network, tunnel.PublicPort)]
		var in, out uint64
		var clients int
		if stats != nil {
			in, out, clients = stats.snapshot()
		}
		views = append(views, tunnelView{Mapping: tunnel, In: in, Out: out, Clients: clients})
	}
	return views
}

func validateTunnel(tunnel *proto.Mapping) error {
	tunnel.ID = ""
	tunnel.Name = strings.TrimSpace(tunnel.Name)
	tunnel.TargetAddr = strings.TrimSpace(tunnel.TargetAddr)
	if tunnel.Name == "" {
		return fmt.Errorf("name is required")
	}
	if tunnel.Network != proto.NetworkTCP && tunnel.Network != proto.NetworkUDP && tunnel.Network != proto.NetworkBoth {
		return fmt.Errorf("network must be tcp, udp, or both")
	}
	if _, _, err := net.SplitHostPort(tunnel.TargetAddr); err != nil {
		return fmt.Errorf("target must be host:port: %w", err)
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeAPIError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

func (a *relayAgent) uiPage(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(uiHTML)
}
