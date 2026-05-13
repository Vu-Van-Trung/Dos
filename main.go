package main

import (
	"embed"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"time"

	"ddos-analyzer/internal/server"
)

//go:embed web
var webFS embed.FS

const defaultAddr = "127.0.0.1:8686"

func main() {
	addr := defaultAddr
	if len(os.Args) > 1 {
		addr = os.Args[1]
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("Không thể lắng nghe trên %s: %v", addr, err)
	}

	srv := server.New(webFS)
	url := fmt.Sprintf("http://%s", addr)

	log.Printf("╔══════════════════════════════════════╗")
	log.Printf("║   DDoS Analyzer — Network Monitor    ║")
	log.Printf("╚══════════════════════════════════════╝")
	log.Printf("Truy cập:  %s", url)
	log.Printf("Nhấn Ctrl+C để dừng.")

	go func() {
		time.Sleep(700 * time.Millisecond)
		openBrowser(url)
	}()

	if err := http.Serve(ln, srv); err != nil {
		log.Fatal(err)
	}
}

func openBrowser(url string) {
	var cmd string
	var args []string
	switch runtime.GOOS {
	case "windows":
		cmd, args = "cmd", []string{"/c", "start", url}
	case "darwin":
		cmd, args = "open", []string{url}
	default:
		cmd, args = "xdg-open", []string{url}
	}
	if err := exec.Command(cmd, args...).Start(); err != nil {
		log.Printf("Không thể mở trình duyệt: %v", err)
	}
}
