package capture

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"

	"ddos-analyzer/internal/analyzer"
)

const sep = "\x01" // ASCII SOH — separator an toàn cho tshark -E separator

var tsharkCandidates = []string{
	"tshark",
	`C:\Program Files\Wireshark\tshark.exe`,
	`C:\Program Files (x86)\Wireshark\tshark.exe`,
	"/usr/bin/tshark",
	"/usr/local/bin/tshark",
	"/opt/homebrew/bin/tshark",
}

var fields = []string{
	"frame.number", "frame.time_epoch",         // 0, 1
	"ip.src", "ip.dst", "ip.proto",             // 2, 3, 4
	"tcp.srcport", "tcp.dstport", "tcp.flags",  // 5, 6, 7
	"udp.srcport", "udp.dstport",               // 8, 9
	"icmp.type",                                // 10
	"arp.src.proto_ipv4", "arp.dst.proto_ipv4", // 11, 12
	"frame.len",                                // 13
	"http.request.method",                      // 14 — Layer 7 HTTP
	"dns.flags.response",                       // 15 — Layer 7 DNS
}

var icmpNames = map[int]string{0: "Echo Reply", 3: "Unreachable", 8: "Echo Request", 11: "TTL Exceeded"}

// Interface mô tả một network interface từ tshark -D.
type Interface struct {
	Index int    `json:"index"`
	Name  string `json:"name"`
	Label string `json:"label"`
}

// FindTShark tìm đường dẫn tshark khả dụng đầu tiên.
func FindTShark() string {
	for _, p := range tsharkCandidates {
		if path, err := exec.LookPath(p); err == nil {
			return path
		}
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// GetInterfaces chạy tshark -D và trả về danh sách interface.
func GetInterfaces(tsharkPath string) ([]Interface, error) {
	out, err := execCmd(tsharkPath, []string{"-D"})
	if err != nil {
		return nil, fmt.Errorf("tshark -D thất bại: %w", err)
	}
	re := regexp.MustCompile(`^(\d+)\.\s+(.+)`)
	var ifaces []Interface
	for _, line := range strings.Split(string(out), "\n") {
		m := re.FindStringSubmatch(strings.TrimSpace(line))
		if m == nil {
			continue
		}
		idx, _ := strconv.Atoi(m[1])
		name := strings.TrimSpace(m[2])
		ifaces = append(ifaces, Interface{
			Index: idx,
			Name:  name,
			Label: fmt.Sprintf("%d. %s", idx, name),
		})
	}
	return ifaces, nil
}

// Capture chứa cấu hình và kênh truyền gói tin.
type Capture struct {
	TSharkPath    string
	Interface     string
	BPFFilter     string
	MaxPackets    int
	PacketCh      chan *analyzer.PacketInfo
	StopCh        chan struct{}
	cmd           *exec.Cmd
	counter       int
}

// NewCapture khởi tạo một phiên capture mới.
func NewCapture(tsharkPath, iface, bpfFilter string, maxPkts int) *Capture {
	return &Capture{
		TSharkPath: tsharkPath,
		Interface:  iface,
		BPFFilter:  bpfFilter,
		MaxPackets: maxPkts,
		PacketCh:   make(chan *analyzer.PacketInfo, 512),
		StopCh:     make(chan struct{}),
	}
}

// Start chạy tshark và stream gói tin vào PacketCh.
// Gọi trong goroutine riêng.
func (c *Capture) Start() error {
	args := c.buildArgs()
	c.cmd = exec.Command(c.TSharkPath, args...)

	if runtime.GOOS == "windows" {
		c.cmd.SysProcAttr = hiddenWindow()
	}

	stdout, err := c.cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("stdout pipe: %w", err)
	}
	if err := c.cmd.Start(); err != nil {
		return fmt.Errorf("không thể khởi động tshark: %w", err)
	}

	go func() {
		defer close(c.PacketCh)
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			select {
			case <-c.StopCh:
				return
			default:
			}
			line := scanner.Text()
			if line == "" {
				continue
			}
			pkt := c.parseLine(line)
			if pkt != nil {
				select {
				case c.PacketCh <- pkt:
				case <-c.StopCh:
					return
				}
			}
			if c.MaxPackets > 0 && c.counter >= c.MaxPackets {
				return
			}
		}
	}()

	return nil
}

// Stop dừng capture.
func (c *Capture) Stop() {
	select {
	case <-c.StopCh:
	default:
		close(c.StopCh)
	}
	if c.cmd != nil && c.cmd.Process != nil {
		c.cmd.Process.Kill()
	}
}

func (c *Capture) buildArgs() []string {
	args := []string{"-i", c.Interface, "-l", "-n"}
	if c.BPFFilter != "" {
		args = append(args, "-f", c.BPFFilter)
	}
	if c.MaxPackets > 0 {
		args = append(args, "-c", strconv.Itoa(c.MaxPackets))
	}
	args = append(args,
		"-T", "fields",
		"-E", "separator="+sep,
		"-E", "header=n",
		"-E", "quote=n",
		"-E", "occurrence=f",
	)
	for _, f := range fields {
		args = append(args, "-e", f)
	}
	return args
}

func (c *Capture) parseLine(line string) *analyzer.PacketInfo {
	parts := strings.Split(line, sep)
	for len(parts) < len(fields) {
		parts = append(parts, "")
	}

	frameNo    := parts[0]
	timeEpoch  := parts[1]
	ipSrc      := parts[2]
	ipDst      := parts[3]
	ipProto    := parts[4]
	tcpSport   := parts[5]
	tcpDport   := parts[6]
	tcpFlags   := parts[7]
	udpSport   := parts[8]
	udpDport   := parts[9]
	icmpType   := parts[10]
	arpSrc     := parts[11]
	arpDst     := parts[12]
	frameLen   := parts[13]
	httpMethod := parts[14] // Layer 7
	dnsResp    := parts[15] // Layer 7

	c.counter++

	ts, _ := strconv.ParseFloat(timeEpoch, 64)
	pktLen, _ := strconv.Atoi(frameLen)
	_ = frameNo

	p := &analyzer.PacketInfo{
		Number:    c.counter,
		Timestamp: ts,
		SrcIP:     coalesce(ipSrc, arpSrc, "0.0.0.0"),
		DstIP:     coalesce(ipDst, arpDst, "0.0.0.0"),
		Protocol:  "OTHER",
		Length:    pktLen,
	}

	proto, _ := strconv.Atoi(ipProto)
	switch proto {
	case 6: // TCP
		sport, _ := strconv.Atoi(tcpSport)
		dport, _ := strconv.Atoi(tcpDport)
		p.SrcPort = sport
		p.DstPort = dport
		if tcpFlags != "" {
			fv, err := strconv.ParseInt(strings.TrimPrefix(tcpFlags, "0x"), 16, 64)
			if err == nil {
				p.Flags = analyzer.TCPFlags{
					SYN: fv&0x02 != 0,
					ACK: fv&0x10 != 0,
					FIN: fv&0x01 != 0,
					RST: fv&0x04 != 0,
					PSH: fv&0x08 != 0,
					URG: fv&0x20 != 0,
				}
			}
		}
		p.FlagsStr = p.Flags.String()
		// Layer 7: HTTP method từ tshark field thực tế
		if httpMethod != "" {
			p.HTTPMethod = httpMethod
		}
		switch {
		case sport == 80 || dport == 80:
			p.Protocol = "HTTP"
		case sport == 443 || dport == 443:
			p.Protocol = "HTTPS"
		case sport == 53 || dport == 53:
			p.Protocol = "DNS"
		default:
			p.Protocol = "TCP"
		}
		if httpMethod != "" {
			p.Info = fmt.Sprintf("%s %d → %d [%s]", httpMethod, sport, dport, p.FlagsStr)
		} else {
			p.Info = fmt.Sprintf("%d → %d [%s]", sport, dport, p.FlagsStr)
		}

	case 17: // UDP
		sport, _ := strconv.Atoi(udpSport)
		dport, _ := strconv.Atoi(udpDport)
		p.SrcPort = sport
		p.DstPort = dport
		if sport == 53 || dport == 53 {
			p.Protocol = "DNS"
			// Layer 7: DNS response flag từ tshark
			p.IsDNSResponse = dnsResp == "1"
		} else {
			p.Protocol = "UDP"
		}
		p.Info = fmt.Sprintf("%d → %d", sport, dport)

	case 1: // ICMP
		p.Protocol = "ICMP"
		if icmpType != "" {
			t, _ := strconv.Atoi(icmpType)
			if name, ok := icmpNames[t]; ok {
				p.Info = name
			} else {
				p.Info = fmt.Sprintf("Type %d", t)
			}
		}

	default:
		if ipProto == "" && (arpSrc != "" || arpDst != "") {
			p.Protocol = "ARP"
			p.Info = fmt.Sprintf("ARP %s → %s", arpSrc, arpDst)
		}
	}
	return p
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func coalesce(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func execCmd(name string, args []string) ([]byte, error) {
	cmd := exec.Command(name, args...)
	if runtime.GOOS == "windows" {
		cmd.SysProcAttr = hiddenWindow()
	}
	return cmd.Output()
}
