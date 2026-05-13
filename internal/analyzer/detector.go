package analyzer

import (
	"fmt"
	"sort"
	"strings"
)

// ── Ngưỡng phát hiện ─────────────────────────────────────────────────────────

const (
	synPerSourceThresh  = 50.0  // SYN/s từ 1 IP
	synTotalThresh      = 200.0 // Tổng SYN/s
	udpTotalThresh      = 500.0 // UDP/s
	icmpTotalThresh     = 50.0  // ICMP/s
	httpPerSourceThresh = 100.0 // HTTP req/s từ 1 IP
	volumetricThreshMB  = 5.0   // MB/s
	singleSourceRatio   = 0.40  // 1 IP > 40% tổng traffic
	portScanThresh      = 100   // Số port khác nhau bị scan
)

// DDoSDetector chạy các thuật toán phát hiện tấn công.
type DDoSDetector struct {
	nextID int
}

// Analyze phân tích toàn bộ danh sách gói tin và trả về alerts + stats.
func (d *DDoSDetector) Analyze(packets []PacketInfo) ([]Alert, *NetworkStats) {
	if len(packets) == 0 {
		return nil, &NetworkStats{
			ProtocolCounts: map[string]int{},
			SrcIPCounts:    map[string]int{},
			DstIPCounts:    map[string]int{},
		}
	}

	stats := d.buildStats(packets)
	var alerts []Alert

	alerts = append(alerts, d.detectSYNFlood(packets, stats)...)
	alerts = append(alerts, d.detectUDPFlood(packets, stats)...)
	alerts = append(alerts, d.detectICMPFlood(packets, stats)...)
	alerts = append(alerts, d.detectHTTPFlood(packets, stats)...)
	alerts = append(alerts, d.detectDNSAmplification(packets, stats)...) // Layer 7
	alerts = append(alerts, d.detectVolumetric(packets, stats)...)
	alerts = append(alerts, d.detectSingleSource(packets, stats)...)
	alerts = append(alerts, d.detectPortScan(packets, stats)...)

	// Đánh dấu gói tin nghi ngờ
	flagged := make(map[int]bool)
	for _, a := range alerts {
		for _, id := range a.EvidencePackets {
			flagged[id] = true
		}
	}
	for i := range packets {
		if flagged[packets[i].Number] {
			packets[i].IsSuspicious = true
		}
	}

	// Sắp xếp theo severity
	sevOrder := map[AlertSeverity]int{
		SeverityCritical: 0,
		SeverityHigh:     1,
		SeverityMedium:   2,
		SeverityLow:      3,
	}
	sort.Slice(alerts, func(i, j int) bool {
		return sevOrder[alerts[i].Severity] < sevOrder[alerts[j].Severity]
	})

	return alerts, stats
}

// ── Xây dựng thống kê ────────────────────────────────────────────────────────

func (d *DDoSDetector) buildStats(packets []PacketInfo) *NetworkStats {
	s := &NetworkStats{
		ProtocolCounts: make(map[string]int),
		SrcIPCounts:    make(map[string]int),
		DstIPCounts:    make(map[string]int),
	}
	s.TotalPackets = len(packets)
	s.StartTime = packets[0].Timestamp
	s.EndTime = packets[0].Timestamp

	for _, p := range packets {
		s.TotalBytes += int64(p.Length)
		s.ProtocolCounts[p.Protocol]++
		s.SrcIPCounts[p.SrcIP]++
		s.DstIPCounts[p.DstIP]++
		if p.Timestamp < s.StartTime {
			s.StartTime = p.Timestamp
		}
		if p.Timestamp > s.EndTime {
			s.EndTime = p.Timestamp
		}
	}
	s.Duration = s.EndTime - s.StartTime
	if s.Duration < 0.001 {
		s.Duration = 0.001
	}

	// Buckets theo 1-giây
	n := int(s.Duration) + 1
	if n < 1 {
		n = 1
	}
	pps := make([]float64, n)
	bps := make([]float64, n)
	for _, p := range packets {
		idx := int(p.Timestamp - s.StartTime)
		if idx >= n {
			idx = n - 1
		}
		pps[idx]++
		bps[idx] += float64(p.Length)
	}
	s.PacketsPerSecond = pps
	s.BytesPerSecond = bps
	s.TimeBuckets = make([]float64, n)
	for i := range s.TimeBuckets {
		s.TimeBuckets[i] = s.StartTime + float64(i)
	}
	return s
}

// ── SYN Flood ─────────────────────────────────────────────────────────────────

func (d *DDoSDetector) detectSYNFlood(packets []PacketInfo, stats *NetworkStats) []Alert {
	// Nhóm SYN (không ACK) theo IP nguồn
	bySrc := make(map[string][]PacketInfo)
	for _, p := range packets {
		if p.Flags.SYN && !p.Flags.ACK {
			bySrc[p.SrcIP] = append(bySrc[p.SrcIP], p)
		}
	}
	if len(bySrc) == 0 {
		return nil
	}

	var alerts []Alert

	// Kiểm tra từng nguồn
	for srcIP, pkts := range bySrc {
		rate := float64(len(pkts)) / stats.Duration
		if rate < synPerSourceThresh {
			continue
		}
		sev := d.rateToSev(rate, 300, 100)
		target := topValue(pkts, func(p PacketInfo) string { return p.DstIP })
		alerts = append(alerts, Alert{
			ID:         d.nid(),
			AttackType: AttackSYNFlood,
			Severity:   sev,
			Description: fmt.Sprintf(
				"SYN Flood từ %s — %.0f SYN/s (%d gói, không có ACK phản hồi).",
				srcIP, rate, len(pkts),
			),
			SourceIPs:       []string{srcIP},
			TargetIP:        target,
			PacketCount:     len(pkts),
			Rate:            rate,
			StartTime:       pkts[0].Timestamp,
			EndTime:         pkts[len(pkts)-1].Timestamp,
			EvidencePackets: evidenceIDs(pkts, 200),
			Recommendation: "• Bật SYN Cookies trên server.\n" +
				"• Chặn IP nguồn trên Firewall.\n" +
				"• Rate-limit kết nối TCP mới (iptables/nftables).",
			SeverityColor: d.sevColor(sev),
			SeverityBg:    d.sevBg(sev),
		})
	}

	// Kiểm tra tổng SYN phân tán
	var allSYN []PacketInfo
	for _, pkts := range bySrc {
		allSYN = append(allSYN, pkts...)
	}
	totalRate := float64(len(allSYN)) / stats.Duration
	if totalRate >= synTotalThresh && len(bySrc) > 3 {
		top10 := topN(bySrc, 10)
		alerts = append(alerts, Alert{
			ID:         d.nid(),
			AttackType: AttackSYNFlood,
			Severity:   SeverityHigh,
			Description: fmt.Sprintf(
				"Distributed SYN Flood — %.0f SYN/s từ %d nguồn IP khác nhau.",
				totalRate, len(bySrc),
			),
			SourceIPs:       top10,
			PacketCount:     len(allSYN),
			Rate:            totalRate,
			StartTime:       allSYN[0].Timestamp,
			EndTime:         allSYN[len(allSYN)-1].Timestamp,
			EvidencePackets: evidenceIDs(allSYN, 200),
			Recommendation: "• Triển khai IDS/IPS (Snort/Suricata).\n" +
				"• Dùng CDN / DDoS protection (Cloudflare, AWS Shield).\n" +
				"• Giới hạn connection rate theo subnet.",
			SeverityColor: d.sevColor(SeverityHigh),
			SeverityBg:    d.sevBg(SeverityHigh),
		})
	}
	return alerts
}

// ── UDP Flood ─────────────────────────────────────────────────────────────────

func (d *DDoSDetector) detectUDPFlood(packets []PacketInfo, stats *NetworkStats) []Alert {
	var udps []PacketInfo
	for _, p := range packets {
		if p.Protocol == "UDP" {
			udps = append(udps, p)
		}
	}
	if len(udps) == 0 {
		return nil
	}
	rate := float64(len(udps)) / stats.Duration
	if rate < udpTotalThresh {
		return nil
	}
	sev := d.rateToSev(rate, 2000, 1000)
	srcs := countBy(udps, func(p PacketInfo) string { return p.SrcIP })
	return []Alert{{
		ID:         d.nid(),
		AttackType: AttackUDPFlood,
		Severity:   sev,
		Description: fmt.Sprintf(
			"UDP Flood — %.0f packet/s từ %d nguồn IP. Có thể bão hòa băng thông.",
			rate, len(srcs),
		),
		SourceIPs:       topNMap(srcs, 5),
		TargetIP:        topValue(udps, func(p PacketInfo) string { return p.DstIP }),
		PacketCount:     len(udps),
		Rate:            rate,
		StartTime:       udps[0].Timestamp,
		EndTime:         udps[len(udps)-1].Timestamp,
		EvidencePackets: evidenceIDs(udps, 200),
		Recommendation: "• Chặn UDP từ các IP không tin cậy trên Firewall.\n" +
			"• Rate-limit UDP traffic trên router.\n" +
			"• Kích hoạt tính năng anti-UDP-flood trên router.",
		SeverityColor: d.sevColor(sev),
		SeverityBg:    d.sevBg(sev),
	}}
}

// ── ICMP Flood ────────────────────────────────────────────────────────────────

func (d *DDoSDetector) detectICMPFlood(packets []PacketInfo, stats *NetworkStats) []Alert {
	var icmps []PacketInfo
	for _, p := range packets {
		if p.Protocol == "ICMP" {
			icmps = append(icmps, p)
		}
	}
	if len(icmps) == 0 {
		return nil
	}
	rate := float64(len(icmps)) / stats.Duration
	if rate < icmpTotalThresh {
		return nil
	}
	sev := SeverityMedium
	if rate > 200 {
		sev = SeverityHigh
	}
	srcs := countBy(icmps, func(p PacketInfo) string { return p.SrcIP })
	return []Alert{{
		ID:         d.nid(),
		AttackType: AttackICMPFlood,
		Severity:   sev,
		Description: fmt.Sprintf(
			"ICMP/Ping Flood — %.0f packet/s từ %d nguồn. Có thể là Smurf Attack.",
			rate, len(srcs),
		),
		SourceIPs:       topNMap(srcs, 5),
		TargetIP:        topValue(icmps, func(p PacketInfo) string { return p.DstIP }),
		PacketCount:     len(icmps),
		Rate:            rate,
		StartTime:       icmps[0].Timestamp,
		EndTime:         icmps[len(icmps)-1].Timestamp,
		EvidencePackets: evidenceIDs(icmps, 200),
		Recommendation: "• Chặn ICMP echo-request từ bên ngoài trên Firewall.\n" +
			"• Giới hạn ICMP rate (iptables -m limit).\n" +
			"• Kiểm tra broadcast amplification (Smurf Attack).",
		SeverityColor: d.sevColor(sev),
		SeverityBg:    d.sevBg(sev),
	}}
}

// ── HTTP Flood (Layer 7) ──────────────────────────────────────────────────────

func (d *DDoSDetector) detectHTTPFlood(packets []PacketInfo, stats *NetworkStats) []Alert {
	bySrc := make(map[string][]PacketInfo)
	for _, p := range packets {
		if p.Protocol == "HTTP" || p.Protocol == "HTTPS" {
			bySrc[p.SrcIP] = append(bySrc[p.SrcIP], p)
		}
	}
	var alerts []Alert
	for srcIP, pkts := range bySrc {
		rate := float64(len(pkts)) / stats.Duration
		if rate < httpPerSourceThresh {
			continue
		}
		sev := SeverityMedium
		if rate > 300 {
			sev = SeverityHigh
		}

		// Layer 7: đếm HTTP method từ payload thực tế
		methodCount := make(map[string]int)
		withMethod := 0
		for _, p := range pkts {
			if p.HTTPMethod != "" {
				methodCount[p.HTTPMethod]++
				withMethod++
			}
		}
		methodSummary := ""
		if withMethod > 0 {
			parts := make([]string, 0, len(methodCount))
			for m, c := range methodCount {
				parts = append(parts, fmt.Sprintf("%s×%d", m, c))
			}
			sort.Strings(parts)
			methodSummary = " [" + strings.Join(parts, " ") + "]"
		}

		alerts = append(alerts, Alert{
			ID:         d.nid(),
			AttackType: AttackHTTPFlood,
			Severity:   sev,
			Description: fmt.Sprintf(
				"HTTP Flood từ %s — %.0f req/s (%d packets)%s.",
				srcIP, rate, len(pkts), methodSummary,
			),
			SourceIPs:       []string{srcIP},
			TargetIP:        topValue(pkts, func(p PacketInfo) string { return p.DstIP }),
			PacketCount:     len(pkts),
			Rate:            rate,
			StartTime:       pkts[0].Timestamp,
			EndTime:         pkts[len(pkts)-1].Timestamp,
			EvidencePackets: evidenceIDs(pkts, 200),
			Recommendation: "• Triển khai Web Application Firewall (WAF).\n" +
				"• Bật CAPTCHA cho request bất thường.\n" +
				"• Rate-limit HTTP theo IP (Nginx / HAProxy).\n" +
				"• Phân tích User-Agent để phát hiện bot.",
			SeverityColor: d.sevColor(sev),
			SeverityBg:    d.sevBg(sev),
		})
	}
	return alerts
}

// ── DNS Amplification (Layer 7) ───────────────────────────────────────────────

func (d *DDoSDetector) detectDNSAmplification(packets []PacketInfo, stats *NetworkStats) []Alert {
	// Thu thập DNS query bytes (client → resolver) và response bytes (resolver → victim)
	queryBytes := make(map[string]int64)  // victim IP → tổng bytes query gửi đi
	respByVictim := make(map[string][]PacketInfo) // victim IP → các response nhận về

	for _, p := range packets {
		if p.Protocol != "DNS" {
			continue
		}
		if p.IsDNSResponse {
			// Response: src=resolver (sport=53), dst=victim
			respByVictim[p.DstIP] = append(respByVictim[p.DstIP], p)
		} else {
			// Query: src=client, dst=resolver (dport=53)
			queryBytes[p.SrcIP] += int64(p.Length)
		}
	}

	const minRespPkts = 20
	const minAmplFactor = 5.0

	var alerts []Alert
	for victimIP, respPkts := range respByVictim {
		if len(respPkts) < minRespPkts {
			continue
		}
		var totalRespBytes int64
		for _, p := range respPkts {
			totalRespBytes += int64(p.Length)
		}
		qb := queryBytes[victimIP]
		if qb == 0 {
			qb = 1
		}
		amplFactor := float64(totalRespBytes) / float64(qb)
		if amplFactor < minAmplFactor {
			continue
		}
		respRate := float64(len(respPkts)) / stats.Duration
		sev := SeverityMedium
		if amplFactor > 50 {
			sev = SeverityHigh
		}
		if amplFactor > 100 {
			sev = SeverityCritical
		}
		resolvers := countBy(respPkts, func(p PacketInfo) string { return p.SrcIP })
		alerts = append(alerts, Alert{
			ID:         d.nid(),
			AttackType: AttackDNSAmplification,
			Severity:   sev,
			Description: fmt.Sprintf(
				"DNS Amplification nhắm vào %s — %.0f KB response từ %d DNS resolver (hệ số khuếch đại ×%.0f).",
				victimIP, float64(totalRespBytes)/1024, len(resolvers), amplFactor,
			),
			SourceIPs:       topNMap(resolvers, 5),
			TargetIP:        victimIP,
			PacketCount:     len(respPkts),
			Rate:            respRate,
			StartTime:       respPkts[0].Timestamp,
			EndTime:         respPkts[len(respPkts)-1].Timestamp,
			EvidencePackets: evidenceIDs(respPkts, 200),
			Recommendation: "• Chặn DNS response từ các IP resolver không tin cậy.\n" +
				"• Vô hiệu hóa open DNS resolver trên hệ thống.\n" +
				"• Bật Response Rate Limiting (RRL) trên DNS server.\n" +
				"• Dùng DNS firewall lọc response bất thường.",
			SeverityColor: d.sevColor(sev),
			SeverityBg:    d.sevBg(sev),
		})
	}
	return alerts
}

// ── Volumetric ────────────────────────────────────────────────────────────────

func (d *DDoSDetector) detectVolumetric(packets []PacketInfo, stats *NetworkStats) []Alert {
	bwMB := stats.AvgBandwidthMBps()
	if bwMB < volumetricThreshMB {
		return nil
	}
	sev := d.rateToSev(bwMB, 100, 20)
	srcs := countBy(packets, func(p PacketInfo) string { return p.SrcIP })
	return []Alert{{
		ID:         d.nid(),
		AttackType: AttackVolumetric,
		Severity:   sev,
		Description: fmt.Sprintf(
			"Tấn công Volumetric — Băng thông %.2f MB/s vượt ngưỡng %.0f MB/s.",
			bwMB, volumetricThreshMB,
		),
		SourceIPs:       topNMap(srcs, 5),
		PacketCount:     stats.TotalPackets,
		Rate:            stats.AvgPacketRate(),
		StartTime:       stats.StartTime,
		EndTime:         stats.EndTime,
		EvidencePackets: evidenceIDs(packets, 100),
		Recommendation: "• Dùng CDN (Cloudflare, Akamai) để hấp thụ traffic.\n" +
			"• Liên hệ ISP để null-route IP đích tạm thời.\n" +
			"• Tăng băng thông hoặc dùng anycast routing.",
		SeverityColor: d.sevColor(sev),
		SeverityBg:    d.sevBg(sev),
	}}
}

// ── Single Source DoS ─────────────────────────────────────────────────────────

func (d *DDoSDetector) detectSingleSource(packets []PacketInfo, stats *NetworkStats) []Alert {
	if len(packets) == 0 {
		return nil
	}
	total := len(packets)
	srcs := countBy(packets, func(p PacketInfo) string { return p.SrcIP })
	sorted := topNMap(srcs, 3)

	var alerts []Alert
	for _, srcIP := range sorted {
		count := srcs[srcIP]
		ratio := float64(count) / float64(total)
		if ratio < singleSourceRatio || count < 50 {
			continue
		}
		rate := float64(count) / stats.Duration
		sev := SeverityMedium
		if ratio > 0.7 {
			sev = SeverityHigh
		}
		var srcPkts []PacketInfo
		for _, p := range packets {
			if p.SrcIP == srcIP {
				srcPkts = append(srcPkts, p)
			}
		}
		target := topValue(srcPkts, func(p PacketInfo) string { return p.DstIP })
		alerts = append(alerts, Alert{
			ID:         d.nid(),
			AttackType: AttackSingleSrc,
			Severity:   sev,
			Description: fmt.Sprintf(
				"DoS đơn nguồn — %s chiếm %.1f%% traffic (%d/%d packets, %.0f pkt/s).",
				srcIP, ratio*100, count, total, rate,
			),
			SourceIPs:       []string{srcIP},
			TargetIP:        target,
			PacketCount:     count,
			Rate:            rate,
			StartTime:       srcPkts[0].Timestamp,
			EndTime:         srcPkts[len(srcPkts)-1].Timestamp,
			EvidencePackets: evidenceIDs(srcPkts, 200),
			Recommendation: "• Chặn ngay IP nguồn trên Firewall.\n" +
				"• Thêm rule ACL trên router.\n" +
				"• Theo dõi IP này trong các phiên tiếp theo.",
			SeverityColor: d.sevColor(sev),
			SeverityBg:    d.sevBg(sev),
		})
	}
	return alerts
}

// ── Port Scan (chỉ TCP) ───────────────────────────────────────────────────────

func (d *DDoSDetector) detectPortScan(packets []PacketInfo, stats *NetworkStats) []Alert {
	type key struct{ src, dst string }
	pairPorts := make(map[key]map[int]bool)
	pairPkts := make(map[key][]PacketInfo)

	for _, p := range packets {
		if p.Protocol != "TCP" && p.Protocol != "HTTP" && p.Protocol != "HTTPS" {
			continue
		}
		if p.DstPort == 0 {
			continue
		}
		k := key{p.SrcIP, p.DstIP}
		if pairPorts[k] == nil {
			pairPorts[k] = make(map[int]bool)
		}
		pairPorts[k][p.DstPort] = true
		pairPkts[k] = append(pairPkts[k], p)
	}

	// Mỗi IP nguồn chỉ báo cáo pair có nhiều port nhất (tránh trùng lặp)
	best := make(map[string]struct {
		dst   string
		count int
	})
	for k, ports := range pairPorts {
		if len(ports) >= portScanThresh {
			if cur, ok := best[k.src]; !ok || len(ports) > cur.count {
				best[k.src] = struct {
					dst   string
					count int
				}{k.dst, len(ports)}
			}
		}
	}

	var alerts []Alert
	for srcIP, b := range best {
		pkts := pairPkts[key{srcIP, b.dst}]
		rate := float64(len(pkts)) / stats.Duration
		sev := SeverityMedium
		if b.count > 200 {
			sev = SeverityHigh
		}
		alerts = append(alerts, Alert{
			ID:         d.nid(),
			AttackType: AttackPortScan,
			Severity:   sev,
			Description: fmt.Sprintf(
				"Port Scan — %s quét %d port trên %s (%.0f pkt/s). Có thể là bước trinh sát.",
				srcIP, b.count, b.dst, rate,
			),
			SourceIPs:       []string{srcIP},
			TargetIP:        b.dst,
			PacketCount:     len(pkts),
			Rate:            rate,
			StartTime:       pkts[0].Timestamp,
			EndTime:         pkts[len(pkts)-1].Timestamp,
			EvidencePackets: evidenceIDs(pkts, 200),
			Recommendation: "• Chặn IP scanner trên Firewall.\n" +
				"• Tắt các port không cần thiết.\n" +
				"• Cài đặt honeypot để phát hiện sớm.",
			SeverityColor: d.sevColor(sev),
			SeverityBg:    d.sevBg(sev),
		})
	}
	return alerts
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func (d *DDoSDetector) nid() int {
	d.nextID++
	return d.nextID
}

func (d *DDoSDetector) rateToSev(rate, critThresh, highThresh float64) AlertSeverity {
	if rate > critThresh {
		return SeverityCritical
	}
	if rate > highThresh {
		return SeverityHigh
	}
	return SeverityMedium
}

func (d *DDoSDetector) sevColor(s AlertSeverity) string {
	m := map[AlertSeverity]string{
		SeverityLow:      "#F9E64F",
		SeverityMedium:   "#FAB387",
		SeverityHigh:     "#F38BA8",
		SeverityCritical: "#D20F39",
	}
	if c, ok := m[s]; ok {
		return c
	}
	return "#CDD6F4"
}

func (d *DDoSDetector) sevBg(s AlertSeverity) string {
	m := map[AlertSeverity]string{
		SeverityLow:      "#2d2b1a",
		SeverityMedium:   "#2d1f0d",
		SeverityHigh:     "#2d1015",
		SeverityCritical: "#3a0808",
	}
	if c, ok := m[s]; ok {
		return c
	}
	return "#1e1e2e"
}

// countBy nhóm gói tin theo key và đếm.
func countBy(packets []PacketInfo, keyFn func(PacketInfo) string) map[string]int {
	m := make(map[string]int)
	for _, p := range packets {
		m[keyFn(p)]++
	}
	return m
}

// topValue trả về giá trị xuất hiện nhiều nhất.
func topValue(packets []PacketInfo, keyFn func(PacketInfo) string) string {
	m := countBy(packets, keyFn)
	best := ""
	max := 0
	for k, v := range m {
		if v > max {
			max = v
			best = k
		}
	}
	return best
}

// topNMap trả về n key có count cao nhất.
func topNMap(m map[string]int, n int) []string {
	type kv struct {
		k string
		v int
	}
	var pairs []kv
	for k, v := range m {
		pairs = append(pairs, kv{k, v})
	}
	sort.Slice(pairs, func(i, j int) bool { return pairs[i].v > pairs[j].v })
	if n > len(pairs) {
		n = len(pairs)
	}
	out := make([]string, n)
	for i := range out {
		out[i] = pairs[i].k
	}
	return out
}

// topN trả về n key của map có value lớn nhất.
func topN(m map[string][]PacketInfo, n int) []string {
	type kv struct {
		k string
		v int
	}
	var pairs []kv
	for k, v := range m {
		pairs = append(pairs, kv{k, len(v)})
	}
	sort.Slice(pairs, func(i, j int) bool { return pairs[i].v > pairs[j].v })
	if n > len(pairs) {
		n = len(pairs)
	}
	out := make([]string, n)
	for i := range out {
		out[i] = pairs[i].k
	}
	return out
}

// evidenceIDs trả về tối đa n packet number.
func evidenceIDs(pkts []PacketInfo, max int) []int {
	if len(pkts) < max {
		max = len(pkts)
	}
	ids := make([]int, max)
	for i := range ids {
		ids[i] = pkts[i].Number
	}
	return ids
}
