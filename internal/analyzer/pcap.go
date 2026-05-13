package analyzer

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
)

// LoadPCAP đọc file .pcap thuần Go (không cần libpcap).
// Hỗ trợ định dạng PCAP classic (magic 0xa1b2c3d4 / 0xd4c3b2a1).
func LoadPCAP(path string, progressCh chan<- [2]int) ([]PacketInfo, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	// Đọc global header (24 bytes)
	var magic uint32
	if err := binary.Read(f, binary.LittleEndian, &magic); err != nil {
		return nil, fmt.Errorf("đọc magic bytes thất bại: %w", err)
	}

	var order binary.ByteOrder
	switch magic {
	case 0xa1b2c3d4:
		order = binary.LittleEndian
	case 0xd4c3b2a1:
		order = binary.BigEndian
	case 0xa1b23c4d, 0x4d3cb2a1:
		// nanosecond variant — treat like microsecond
		if magic == 0xa1b23c4d {
			order = binary.LittleEndian
		} else {
			order = binary.BigEndian
		}
	default:
		return nil, fmt.Errorf("định dạng không được hỗ trợ (magic=0x%08X). Chỉ hỗ trợ .pcap chuẩn", magic)
	}

	// Phần còn lại của global header (20 bytes)
	var (
		verMaj, verMin uint16
		_              int32  // thiszone
		_              uint32 // sigfigs
		snapLen        uint32
		_              uint32 // network (link type)
	)
	if err := binary.Read(f, order, &verMaj); err != nil {
		return nil, err
	}
	if err := binary.Read(f, order, &verMin); err != nil {
		return nil, err
	}
	_ = verMaj
	_ = verMin
	// thiszone
	var i32 int32
	binary.Read(f, order, &i32)
	// sigfigs
	var u32 uint32
	binary.Read(f, order, &u32)
	// snaplen
	binary.Read(f, order, &snapLen)
	// network
	binary.Read(f, order, &u32)

	var packets []PacketInfo
	counter := 0

	// Đếm tổng để report progress (optional second pass)
	fileSize, _ := f.Seek(0, io.SeekEnd)
	f.Seek(24, io.SeekStart) // reset to after global header

	for {
		// Per-packet header (16 bytes)
		var tsSec, tsUsec, inclLen, origLen uint32
		if err := binary.Read(f, order, &tsSec); err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				break
			}
			return nil, fmt.Errorf("lỗi đọc packet header: %w", err)
		}
		binary.Read(f, order, &tsUsec)
		binary.Read(f, order, &inclLen)
		binary.Read(f, order, &origLen)

		if inclLen > snapLen+100 || inclLen > 65536 {
			break // dữ liệu bị hỏng
		}

		rawData := make([]byte, inclLen)
		if _, err := io.ReadFull(f, rawData); err != nil {
			break
		}

		counter++
		ts := float64(tsSec) + float64(tsUsec)/1e6
		pkt := parseRawPacket(rawData, counter, ts, int(origLen))
		if pkt != nil {
			packets = append(packets, *pkt)
		}

		if progressCh != nil && counter%500 == 0 {
			pos, _ := f.Seek(0, io.SeekCurrent)
			progressCh <- [2]int{int(pos), int(fileSize)}
		}
	}

	if progressCh != nil {
		progressCh <- [2]int{1, 1}
	}
	return packets, nil
}

// parseRawPacket phân tích dữ liệu thô của gói tin Ethernet/IP/TCP|UDP|ICMP.
func parseRawPacket(data []byte, n int, ts float64, origLen int) *PacketInfo {
	p := &PacketInfo{
		Number:    n,
		Timestamp: ts,
		SrcIP:     "0.0.0.0",
		DstIP:     "0.0.0.0",
		Protocol:  "OTHER",
		Length:    origLen,
	}
	if origLen == 0 {
		p.Length = len(data)
	}

	// Ethernet header — 14 bytes
	if len(data) < 14 {
		return p
	}
	etherType := binary.BigEndian.Uint16(data[12:14])

	// ARP
	if etherType == 0x0806 {
		p.Protocol = "ARP"
		if len(data) >= 14+8+6+4+6+4 {
			// ARP sender/target PA
			p.SrcIP = fmt.Sprintf("%d.%d.%d.%d", data[28], data[29], data[30], data[31])
			p.DstIP = fmt.Sprintf("%d.%d.%d.%d", data[38], data[39], data[40], data[41])
		}
		return p
	}

	// IPv4
	if etherType != 0x0800 {
		return p
	}
	ip := data[14:]
	if len(ip) < 20 {
		return p
	}
	ihl := int((ip[0] & 0x0F) * 4)
	if ihl < 20 || len(ip) < ihl {
		return p
	}
	proto := ip[9]
	p.SrcIP = fmt.Sprintf("%d.%d.%d.%d", ip[12], ip[13], ip[14], ip[15])
	p.DstIP = fmt.Sprintf("%d.%d.%d.%d", ip[16], ip[17], ip[18], ip[19])

	transport := ip[ihl:]

	switch proto {
	case 6: // TCP
		if len(transport) < 20 {
			return p
		}
		p.SrcPort = int(binary.BigEndian.Uint16(transport[0:2]))
		p.DstPort = int(binary.BigEndian.Uint16(transport[2:4]))
		flagByte := transport[13]
		p.Flags = TCPFlags{
			SYN: flagByte&0x02 != 0,
			ACK: flagByte&0x10 != 0,
			FIN: flagByte&0x01 != 0,
			RST: flagByte&0x04 != 0,
			PSH: flagByte&0x08 != 0,
			URG: flagByte&0x20 != 0,
		}
		p.FlagsStr = p.Flags.String()
		switch {
		case p.SrcPort == 80 || p.DstPort == 80:
			p.Protocol = "HTTP"
		case p.SrcPort == 443 || p.DstPort == 443:
			p.Protocol = "HTTPS"
		case p.SrcPort == 53 || p.DstPort == 53:
			p.Protocol = "DNS"
		default:
			p.Protocol = "TCP"
		}
		// Layer 7: trích xuất HTTP method từ TCP payload
		tcpHdrLen := int((transport[12] >> 4) * 4)
		if tcpHdrLen >= 20 && len(transport) > tcpHdrLen {
			p.HTTPMethod = extractHTTPMethod(transport[tcpHdrLen:])
		}
		if p.HTTPMethod != "" {
			p.Info = fmt.Sprintf("%s %d → %d [%s]", p.HTTPMethod, p.SrcPort, p.DstPort, p.FlagsStr)
		} else {
			p.Info = fmt.Sprintf("%d → %d [%s]", p.SrcPort, p.DstPort, p.FlagsStr)
		}

	case 17: // UDP
		if len(transport) < 8 {
			return p
		}
		p.SrcPort = int(binary.BigEndian.Uint16(transport[0:2]))
		p.DstPort = int(binary.BigEndian.Uint16(transport[2:4]))
		if p.SrcPort == 53 || p.DstPort == 53 {
			p.Protocol = "DNS"
			// Layer 7: phân tích DNS QR bit (byte 2-3 của DNS header = UDP payload offset 8)
			if len(transport) >= 12 {
				dnsFlags := binary.BigEndian.Uint16(transport[10:12])
				p.IsDNSResponse = dnsFlags&0x8000 != 0
			}
		} else {
			p.Protocol = "UDP"
		}
		p.Info = fmt.Sprintf("%d → %d", p.SrcPort, p.DstPort)

	case 1: // ICMP
		p.Protocol = "ICMP"
		if len(transport) >= 1 {
			icmpNames := map[byte]string{0: "Echo Reply", 3: "Unreachable", 8: "Echo Request", 11: "TTL Exceeded"}
			if name, ok := icmpNames[transport[0]]; ok {
				p.Info = name
			} else {
				p.Info = fmt.Sprintf("Type %d", transport[0])
			}
		}
	}
	return p
}

// extractHTTPMethod nhận diện HTTP request method từ đầu TCP payload.
func extractHTTPMethod(payload []byte) string {
	if len(payload) < 4 {
		return ""
	}
	for _, m := range []string{"GET", "POST", "HEAD", "PUT", "DELETE", "PATCH", "OPTIONS"} {
		if len(payload) > len(m) && string(payload[:len(m)]) == m && payload[len(m)] == ' ' {
			return m
		}
	}
	return ""
}
