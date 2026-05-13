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

### 1. Cài Go 1.21+

```bash
# Kiểm tra phiên bản hiện tại
go version

# Nếu chưa có hoặc < 1.21 — cài từ nguồn chính thức
wget https://go.dev/dl/go1.23.4.linux-amd64.tar.gz
sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf go1.23.4.linux-amd64.tar.gz

# Thêm vào PATH (thêm vào ~/.bashrc hoặc ~/.zshrc)
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
source ~/.bashrc

go version   # => go version go1.23.4 linux/amd64
```

### 2. Cài TShark

```bash
sudo apt update
sudo apt install -y tshark

# Cho phép user không phải root bắt gói tin
sudo dpkg-reconfigure wireshark-common   # chọn Yes
sudo usermod -aG wireshark $USER
newgrp wireshark                         # hoặc đăng xuất / đăng nhập lại
```

### 3. Clone và build

```bash
git clone https://github.com/Vu-Van-Trung/Dos.git
cd Dos

# Tải dependency
go mod tidy

# Build (tạo file thực thi)
go build -o ddos-analyzer .
```

### 4. Chạy

```bash
# Chạy bình thường (PCAP + live capture nếu đã add vào group wireshark)
./ddos-analyzer

# Hoặc chạy với sudo để chắc chắn có quyền bắt gói tin
sudo ./ddos-analyzer
```

Trình duyệt tự mở tại `http://127.0.0.1:8686`.  
Nếu không tự mở: `xdg-open http://127.0.0.1:8686`

### 5. (Tùy chọn) Dùng không cần sudo với setcap

```bash
# Cấp quyền capture cho binary thay vì dùng sudo
sudo setcap cap_net_raw,cap_net_admin+eip ./ddos-analyzer

./ddos-analyzer   # không cần sudo
```

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
