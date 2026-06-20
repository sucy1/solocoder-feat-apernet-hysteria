package multilisten

import (
	"encoding/json"
	"net/http"

	"github.com/apernet/hysteria/core/v2/server"
)

type HTTPHandler struct {
	manager  PortManager
	hyConfig *server.Config
	secret   string
}

func NewHTTPHandler(manager PortManager, hyConfig *server.Config, secret string) *HTTPHandler {
	return &HTTPHandler{
		manager:  manager,
		hyConfig: hyConfig,
		secret:   secret,
	}
}

func (h *HTTPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.secret != "" && r.Header.Get("Authorization") != h.secret {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	switch r.URL.Path {
	case "/ports":
		switch r.Method {
		case http.MethodGet:
			h.listPorts(w, r)
		case http.MethodPost:
			h.addPort(w, r)
		case http.MethodDelete:
			h.removePort(w, r)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	default:
		http.Error(w, "not found", http.StatusNotFound)
	}
}

type addPortRequest struct {
	Addr     string `json:"addr"`
	Protocol string `json:"protocol"`
	ObfsType string `json:"obfsType"`
}

func (h *HTTPHandler) listPorts(w http.ResponseWriter, r *http.Request) {
	ports := h.manager.ListPorts()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(ports)
}

func (h *HTTPHandler) addPort(w http.ResponseWriter, r *http.Request) {
	var req addPortRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	cfg := ListenConfig{
		Addr:     req.Addr,
		Protocol: req.Protocol,
		ObfsType: req.ObfsType,
	}
	if err := h.manager.AddPort(cfg, h.hyConfig); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("port added"))
}

func (h *HTTPHandler) removePort(w http.ResponseWriter, r *http.Request) {
	addr := r.URL.Query().Get("addr")
	if addr == "" {
		http.Error(w, "addr parameter is required", http.StatusBadRequest)
		return
	}
	if err := h.manager.RemovePort(addr); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("port removed"))
}
