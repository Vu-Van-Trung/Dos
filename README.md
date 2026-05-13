# DDoS Analyzer — Network Monitor

Công cụ phân tích và phát hiện tấn công DDoS theo thời gian thực, viết bằng Go thuần (không CGO).  
Hỗ trợ đọc file `.pcap` và bắt gói tin trực tiếp qua TShark.

![Go](https://img.shields.io/badge/Go-1.21+-00ADD8?logo=go) ![Bootstrap](https://img.shields.io/badge/Bootstrap-5.3-7952B3?logo=bootstrap) ![License](https://img.shields.io/badge/License-MIT-green)

---

## Tính năng

| Tính năng | Mô tả |
|-----------|-------|
| **Phân tích PCAP** | Kéo thả file `.pcap` — parser thuần Go, không cần libpcap |
| **Live Capture** | Bắt gói tin thời gian thực qua TShark subprocess |
| **7 loại phát hiện** | SYN Flood, UDP Flood, ICMP Flood, HTTP Flood, Volumetric, Single-Source DoS, Port Scan |
| **Dashboard** | Biểu đồ Pkt/s (line), phân bổ giao thức (pie), Top-10 IP nguồn (bar) |
| **Bảng Packets** | Cuộn thời gian thực, filter theo IP / giao thức |
| **Alerts** | Thẻ cảnh báo có mức độ nghiêm trọng, rate, IP nguồn, khuyến nghị |

---

## Cài đặt trên Kali Linux

### 1. Cài Go 1.21+ từ nguồn chính thức

> ⚠️ **Không dùng `apt install golang-go`** — Kali cài **gccgo** (Go của GCC, phiên bản 1.18) thay vì Go chuẩn, gây lỗi build. Phải cài từ **go.dev**.

```bash
# Tải Go 1.23 (bản stable mới nhất)
wget https://go.dev/dl/go1.23.4.linux-amd64.tar.gz

# Xóa bản cũ (nếu có), cài bản mới vào /usr/local
sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf go1.23.4.linux-amd64.tar.gz

# QUAN TRỌNG: Thêm vào ĐẦU PATH (prepend) để ghi đè gccgo của hệ thống
echo 'export PATH=/usr/local/go/bin:$PATH' >> ~/.bashrc
source ~/.bashrc

# Kiểm tra — phải thấy "go1.23.4" KHÔNG có chữ "gccgo"
go version
# => go version go1.23.4 linux/amd64  ✓
```

> ❌ Nếu thấy `go version go1.18 gccgo ...` — chưa đúng PATH.  
> Chạy lại: `export PATH=/usr/local/go/bin:$PATH` (dùng **prepend**, không phải append `$PATH:...`).

### 2. Cài TShark

```bash
sudo apt update
sudo apt install -y tshark

# Cho phép user thường bắt gói tin (chọn "Yes" khi được hỏi)
sudo dpkg-reconfigure wireshark-common
sudo usermod -aG wireshark $USER
newgrp wireshark          # hoặc đăng xuất / đăng nhập lại
```

### 3. Clone và build

```bash
git clone https://github.com/Vu-Van-Trung/Dos.git
cd Dos

# Hạ go directive xuống 1.18 nếu dùng Go cũ (bỏ qua nếu đã cài 1.23)
# sed -i 's/^go 1.21/go 1.18/' go.mod

# Tải dependency
go mod tidy

# Build — tắt CGO để tránh xung đột linker hệ thống
CGO_ENABLED=0 go build -o ddos-analyzer .
```

### 4. Chạy

```bash
# Cách 1: sudo (đảm bảo quyền capture)
sudo ./ddos-analyzer

# Cách 2: setcap — cấp quyền vĩnh viễn cho binary (không cần sudo)
sudo setcap cap_net_raw,cap_net_admin+eip ./ddos-analyzer
./ddos-analyzer
```

Trình duyệt tự mở tại `http://127.0.0.1:8686`.  
Nếu không tự mở: `xdg-open http://127.0.0.1:8686`

### Troubleshooting

| Lỗi | Nguyên nhân | Cách sửa |
|-----|-------------|----------|
| `go version go1.18 gccgo` | PATH chưa đúng | `export PATH=/usr/local/go/bin:$PATH` |
| `maximum version supported by tidy is 1.18` | Đang dùng gccgo | Xem lỗi trên |
| `/usr/bin/ld: error in Scrt1.o(.sframe)` | Linker hệ thống xung đột | Thêm `CGO_ENABLED=0` vào lệnh build |
| TShark not found | TShark chưa cài | `sudo apt install tshark` |
| Permission denied (live capture) | Thiếu quyền capture | Dùng `sudo` hoặc `setcap` |

---

## Cài đặt trên Windows

1. Tải **Go 1.21+** từ https://go.dev/dl/ (Windows `.msi`)
2. Tải **Wireshark** (bao gồm TShark) từ https://www.wireshark.org/download.html
3. Mở **PowerShell** (Administrator) và chạy:

```powershell
git clone https://github.com/Vu-Van-Trung/Dos.git
cd Dos
go mod tidy
go build -o ddos-analyzer.exe .
.\ddos-analyzer.exe
```

> **Lưu ý:** Live capture trên Windows yêu cầu chạy với quyền **Administrator**.

---

## Cấu trúc dự án

```
.
├── main.go                    # Entry point — HTTP server + embed web/
├── go.mod
├── internal/
│   ├── analyzer/
│   │   ├── models.go          # PacketInfo, Alert, NetworkStats, ...
│   │   ├── detector.go        # 7 thuật toán phát hiện DDoS
│   │   └── pcap.go            # Parser PCAP thuần Go
│   ├── capture/
│   │   ├── tshark.go          # TShark subprocess + live capture
│   │   ├── syscall_windows.go # Ẩn cửa sổ console (Windows)
│   │   └── syscall_other.go   # Stub cho Linux/macOS
│   └── server/
│       └── server.go          # HTTP routes + WebSocket hub
└── web/
    ├── index.html             # Bootstrap 5.3 dark SPA
    ├── app.js                 # Chart.js + WebSocket client
    └── style.css              # Custom dark theme
```

---

## Ngưỡng phát hiện

| Loại tấn công | Ngưỡng |
|---------------|--------|
| SYN Flood (per IP) | > 50 SYN/s |
| SYN Flood (tổng) | > 200 SYN/s |
| UDP Flood | > 500 UDP/s |
| ICMP Flood | > 50 ICMP/s |
| HTTP Flood (per IP) | > 100 req/s |
| Volumetric | > 5 MB/s |
| Single Source DoS | 1 IP > 40% tổng traffic |
| Port Scan (TCP) | > 100 port khác nhau |

---

## API

| Endpoint | Method | Mô tả |
|----------|--------|-------|
| `/` | GET | Giao diện web |
| `/api/upload` | POST | Upload file `.pcap` (multipart field: `pcap`) |
| `/api/interfaces` | GET | Danh sách network interface từ TShark |
| `/ws` | WebSocket | Stream live capture + kết quả phân tích |

### WebSocket Protocol

**Client → Server**
```json
{ "type": "start_capture", "iface": "eth0", "filter": "tcp", "max_pkts": 0 }
{ "type": "stop_capture" }
```

**Server → Client**
```json
{ "type": "capture_started" }
{ "type": "live_update", "data": { ...AnalysisResult } }
{ "type": "capture_stopped" }
{ "type": "error", "message": "..." }
```

---

## License

MIT
