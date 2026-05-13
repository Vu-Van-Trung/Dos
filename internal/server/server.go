package server

import (
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"ddos-analyzer/internal/analyzer"
	"ddos-analyzer/internal/capture"

	"github.com/gorilla/websocket"
)

var mimeTypes = map[string]string{
	".html": "text/html; charset=utf-8",
	".js":   "application/javascript; charset=utf-8",
	".css":  "text/css; charset=utf-8",
	".json": "application/json; charset=utf-8",
	".png":  "image/png",
	".svg":  "image/svg+xml",
	".ico":  "image/x-icon",
}

type server struct {
	webFS    embed.FS
	upgrader websocket.Upgrader
}

// New returns an http.Handler that serves the embedded web UI and API.
func New(webFS embed.FS) http.Handler {
	s := &server{
		webFS: webFS,
		upgrader: websocket.Upgrader{
			ReadBufferSize:  1024,
			WriteBufferSize: 64 * 1024,
			CheckOrigin:     func(r *http.Request) bool { return true },
		},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/interfaces", s.handleInterfaces)
	mux.HandleFunc("/api/upload", s.handleUpload)
	mux.HandleFunc("/ws", s.handleWS)
	mux.HandleFunc("/", s.handleStatic)
	return mux
}

func (s *server) handleStatic(w http.ResponseWriter, r *http.Request) {
	urlPath := r.URL.Path
	if urlPath == "/" {
		urlPath = "/index.html"
	}
	data, err := s.webFS.ReadFile("web" + urlPath)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	ct := mimeTypes[filepath.Ext(urlPath)]
	if ct == "" {
		ct = http.DetectContentType(data)
	}
	w.Header().Set("Content-Type", ct)
	w.Write(data)
}

func (s *server) handleInterfaces(w http.ResponseWriter, r *http.Request) {
	tsharkPath := capture.FindTShark()
	if tsharkPath == "" {
		writeJSON(w, http.StatusServiceUnavailable,
			map[string]string{"error": "TShark not found. Please install Wireshark."})
		return
	}
	ifaces, err := capture.GetInterfaces(tsharkPath)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, ifaces)
}

func (s *server) handleUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseMultipartForm(100 << 20); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "cannot parse multipart form"})
		return
	}
	file, _, err := r.FormFile("pcap")
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "pcap field missing"})
		return
	}
	defer file.Close()

	tmp, err := os.CreateTemp("", "ddos-*.pcap")
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	defer os.Remove(tmp.Name())
	if _, err := io.Copy(tmp, file); err != nil {
		tmp.Close()
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	tmp.Close()

	packets, err := analyzer.LoadPCAP(tmp.Name(), nil)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	det := &analyzer.DDoSDetector{}
	alerts, stats := det.Analyze(packets)

	display := packets
	if len(display) > 5000 {
		display = display[len(display)-5000:]
	}
	writeJSON(w, http.StatusOK, &analyzer.AnalysisResult{
		Packets:      display,
		Alerts:       alerts,
		Stats:        stats,
		TotalPackets: len(packets),
	})
}

type clientMsg struct {
	Type    string `json:"type"`
	Iface   string `json:"iface"`
	Filter  string `json:"filter"`
	MaxPkts int    `json:"max_pkts"`
}

func (s *server) handleWS(w http.ResponseWriter, r *http.Request) {
	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WS upgrade error: %v", err)
		return
	}
	defer conn.Close()

	var (
		mu      sync.Mutex
		capSess *capture.Capture
	)

	send := func(msg analyzer.WSMessage) {
		mu.Lock()
		defer mu.Unlock()
		if err := conn.WriteJSON(msg); err != nil {
			log.Printf("WS write: %v", err)
		}
	}

	send(analyzer.WSMessage{Type: "connected", Message: "WebSocket connected"})

	for {
		var msg clientMsg
		if err := conn.ReadJSON(&msg); err != nil {
			break
		}
		switch msg.Type {
		case "start_capture":
			if capSess != nil {
				capSess.Stop()
				capSess = nil
			}
			tsharkPath := capture.FindTShark()
			if tsharkPath == "" {
				send(analyzer.WSMessage{Type: "error", Message: "TShark not found. Install Wireshark and restart."})
				continue
			}
			c := capture.NewCapture(tsharkPath, msg.Iface, msg.Filter, msg.MaxPkts)
			if err := c.Start(); err != nil {
				send(analyzer.WSMessage{Type: "error", Message: fmt.Sprintf("Start capture failed: %v", err)})
				continue
			}
			capSess = c
			send(analyzer.WSMessage{Type: "capture_started"})

			go func(c *capture.Capture) {
				var accumulated []analyzer.PacketInfo
				ticker := time.NewTicker(800 * time.Millisecond)
				defer ticker.Stop()

				flush := func() {
					if len(accumulated) == 0 {
						return
					}
					det := &analyzer.DDoSDetector{}
					alerts, stats := det.Analyze(accumulated)
					display := accumulated
					if len(display) > 5000 {
						display = display[len(display)-5000:]
					}
					send(analyzer.WSMessage{
						Type: "live_update",
						Data: &analyzer.AnalysisResult{
							Packets:      display,
							Alerts:       alerts,
							Stats:        stats,
							TotalPackets: len(accumulated),
						},
					})
				}

				for {
					select {
					case pkt, ok := <-c.PacketCh:
						if !ok {
							flush()
							send(analyzer.WSMessage{Type: "capture_stopped"})
							return
						}
						accumulated = append(accumulated, *pkt)
					case <-ticker.C:
						flush()
					}
				}
			}(c)

		case "stop_capture":
			if capSess != nil {
				capSess.Stop()
				capSess = nil
			}
		}
	}

	if capSess != nil {
		capSess.Stop()
	}
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
