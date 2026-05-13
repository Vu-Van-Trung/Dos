package analyzer

// AlertSeverity phân loại mức độ nghiêm trọng của cảnh báo.
type AlertSeverity string

const (
	SeverityLow      AlertSeverity = "LOW"
	SeverityMedium   AlertSeverity = "MEDIUM"
	SeverityHigh     AlertSeverity = "HIGH"
	SeverityCritical AlertSeverity = "CRITICAL"
)

// AttackType phân loại kiểu tấn công DDoS.
type AttackType string

const (
	AttackSYNFlood   AttackType = "SYN Flood"
	AttackUDPFlood   AttackType = "UDP Flood"
	AttackICMPFlood  AttackType = "ICMP/Ping Flood"
	AttackHTTPFlood  AttackType = "HTTP Flood"
	AttackVolumetric AttackType = "Volumetric Attack"
	AttackSingleSrc  AttackType = "Single Source DoS"
	AttackPortScan   AttackType = "Port Scan"
)

// TCPFlags giữ trạng thái các bit cờ TCP.
type TCPFlags struct {
	SYN bool `json:"syn"`
	ACK bool `json:"ack"`
	FIN bool `json:"fin"`
	RST bool `json:"rst"`
	PSH bool `json:"psh"`
	URG bool `json:"urg"`
}

func (f TCPFlags) String() string {
	out := ""
	if f.SYN {
		out += "SYN "
	}
	if f.ACK {
		out += "ACK "
	}
	if f.FIN {
		out += "FIN "
	}
	if f.RST {
		out += "RST "
	}
	if f.PSH {
		out += "PSH "
	}
	if f.URG {
		out += "URG "
	}
	if len(out) > 0 {
		return out[:len(out)-1]
	}
	return ""
}

// PacketInfo chứa thông tin phân tích của một gói tin mạng.
type PacketInfo struct {
	Number       int      `json:"number"`
	Timestamp    float64  `json:"timestamp"`
	SrcIP        string   `json:"src_ip"`
	DstIP        string   `json:"dst_ip"`
	SrcPort      int      `json:"src_port,omitempty"`
	DstPort      int      `json:"dst_port,omitempty"`
	Protocol     string   `json:"protocol"`
	Length       int      `json:"length"`
	Flags        TCPFlags `json:"flags"`
	FlagsStr     string   `json:"flags_str"`
	Info         string   `json:"info"`
	IsSuspicious bool     `json:"is_suspicious"`
}

// Alert đại diện cho một mối đe dọa bảo mật được phát hiện.
type Alert struct {
	ID              int           `json:"id"`
	AttackType      AttackType    `json:"attack_type"`
	Severity        AlertSeverity `json:"severity"`
	Description     string        `json:"description"`
	SourceIPs       []string      `json:"source_ips"`
	TargetIP        string        `json:"target_ip"`
	PacketCount     int           `json:"packet_count"`
	Rate            float64       `json:"rate"`
	StartTime       float64       `json:"start_time"`
	EndTime         float64       `json:"end_time"`
	EvidencePackets []int         `json:"evidence_packets"`
	Recommendation  string        `json:"recommendation"`
	SeverityColor   string        `json:"severity_color"`
	SeverityBg      string        `json:"severity_bg"`
}

// NetworkStats chứa số liệu thống kê về phiên capture.
type NetworkStats struct {
	TotalPackets     int            `json:"total_packets"`
	TotalBytes       int64          `json:"total_bytes"`
	Duration         float64        `json:"duration"`
	StartTime        float64        `json:"start_time"`
	EndTime          float64        `json:"end_time"`
	ProtocolCounts   map[string]int `json:"protocol_counts"`
	SrcIPCounts      map[string]int `json:"src_ip_counts"`
	DstIPCounts      map[string]int `json:"dst_ip_counts"`
	PacketsPerSecond []float64      `json:"packets_per_second"`
	BytesPerSecond   []float64      `json:"bytes_per_second"`
	TimeBuckets      []float64      `json:"time_buckets"`
}

func (s *NetworkStats) AvgPacketRate() float64 {
	if s.Duration > 0 {
		return float64(s.TotalPackets) / s.Duration
	}
	return 0
}

func (s *NetworkStats) AvgBandwidthMBps() float64 {
	if s.Duration > 0 {
		return float64(s.TotalBytes) / s.Duration / 1_000_000
	}
	return 0
}

func (s *NetworkStats) MaxPPS() float64 {
	max := 0.0
	for _, v := range s.PacketsPerSecond {
		if v > max {
			max = v
		}
	}
	return max
}

// AnalysisResult đóng gói kết quả phân tích để gửi về frontend.
type AnalysisResult struct {
	Packets      []PacketInfo  `json:"packets"`
	Alerts       []Alert       `json:"alerts"`
	Stats        *NetworkStats `json:"stats"`
	TotalPackets int           `json:"total_packets"`
}

// WSMessage là định dạng message WebSocket.
type WSMessage struct {
	Type    string      `json:"type"`
	Data    interface{} `json:"data,omitempty"`
	Message string      `json:"message,omitempty"`
}
