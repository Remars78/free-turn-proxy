package routing

import (
	"encoding/binary"
	"net/netip"
)

const (
	ProtoTCP = 6
	ProtoUDP = 17
)

const (
	TCPFlagFIN = 0x01
	TCPFlagSYN = 0x02
	TCPFlagRST = 0x04
	TCPFlagPSH = 0x08
	TCPFlagACK = 0x10
	TCPFlagURG = 0x20
)

type ParsedPacket struct {
	IsIPv4   bool
	IsIPv6   bool
	SrcIP    netip.Addr
	DstIP    netip.Addr
	Protocol uint8
	SrcPort  uint16
	DstPort  uint16
	TCPFlags uint8
	SeqNum   uint32
	AckNum   uint32
	HdrLen   int
	Payload  []byte
}

func ParsePacket(b []byte) (p ParsedPacket, ok bool) {
	if len(b) < 20 {
		return p, false
	}
	version := b[0] >> 4
	if version == 4 {
		ihl := int(b[0]&0x0F) * 4
		if len(b) < ihl || ihl < 20 {
			return p, false
		}
		totalLen := int(binary.BigEndian.Uint16(b[2:4]))
		if totalLen > len(b) {
			totalLen = len(b)
		}
		if totalLen < ihl {
			return p, false
		}

		p.IsIPv4 = true
		p.Protocol = b[9]
		src, _ := netip.AddrFromSlice(b[12:16])
		dst, _ := netip.AddrFromSlice(b[16:20])
		p.SrcIP = src
		p.DstIP = dst

		transport := b[ihl:totalLen]
		if p.Protocol == ProtoTCP && len(transport) >= 20 {
			p.SrcPort = binary.BigEndian.Uint16(transport[0:2])
			p.DstPort = binary.BigEndian.Uint16(transport[2:4])
			p.SeqNum = binary.BigEndian.Uint32(transport[4:8])
			p.AckNum = binary.BigEndian.Uint32(transport[8:12])
			tcpHdrLen := int(transport[12]>>4) * 4
			p.TCPFlags = transport[13]
			p.HdrLen = ihl + tcpHdrLen
			if len(transport) >= tcpHdrLen {
				p.Payload = transport[tcpHdrLen:]
			}
			return p, true
		} else if p.Protocol == ProtoUDP && len(transport) >= 8 {
			p.SrcPort = binary.BigEndian.Uint16(transport[0:2])
			p.DstPort = binary.BigEndian.Uint16(transport[2:4])
			p.HdrLen = ihl + 8
			p.Payload = transport[8:]
			return p, true
		}
		return p, false
	} else if version == 6 {
		if len(b) < 40 {
			return p, false
		}
		payloadLen := int(binary.BigEndian.Uint16(b[4:6]))
		if 40+payloadLen > len(b) {
			payloadLen = len(b) - 40
		}
		p.IsIPv6 = true
		p.Protocol = b[6]
		src, _ := netip.AddrFromSlice(b[8:24])
		dst, _ := netip.AddrFromSlice(b[24:40])
		p.SrcIP = src
		p.DstIP = dst

		transport := b[40 : 40+payloadLen]
		if p.Protocol == ProtoTCP && len(transport) >= 20 {
			p.SrcPort = binary.BigEndian.Uint16(transport[0:2])
			p.DstPort = binary.BigEndian.Uint16(transport[2:4])
			p.SeqNum = binary.BigEndian.Uint32(transport[4:8])
			p.AckNum = binary.BigEndian.Uint32(transport[8:12])
			tcpHdrLen := int(transport[12]>>4) * 4
			p.TCPFlags = transport[13]
			p.HdrLen = 40 + tcpHdrLen
			if len(transport) >= tcpHdrLen {
				p.Payload = transport[tcpHdrLen:]
			}
			return p, true
		} else if p.Protocol == ProtoUDP && len(transport) >= 8 {
			p.SrcPort = binary.BigEndian.Uint16(transport[0:2])
			p.DstPort = binary.BigEndian.Uint16(transport[2:4])
			p.HdrLen = 40 + 8
			p.Payload = transport[8:]
			return p, true
		}
		return p, false
	}
	return p, false
}

func toIPv4(addr netip.Addr) [4]byte {
	if addr.Is4In6() {
		addr = addr.Unmap()
	}
	if addr.Is4() {
		return addr.As4()
	}
	return [4]byte{}
}

func BuildIPv4UDP(srcIP, dstIP netip.Addr, srcPort, dstPort uint16, payload []byte) []byte {
	srcBytes := toIPv4(srcIP)
	dstBytes := toIPv4(dstIP)

	totalLen := 20 + 8 + len(payload)
	b := make([]byte, totalLen)

	b[0] = 0x45
	b[1] = 0
	binary.BigEndian.PutUint16(b[2:4], uint16(totalLen))
	binary.BigEndian.PutUint16(b[4:6], 0)
	binary.BigEndian.PutUint16(b[6:8], 0)
	b[8] = 64
	b[9] = ProtoUDP
	copy(b[12:16], srcBytes[:])
	copy(b[16:20], dstBytes[:])
	binary.BigEndian.PutUint16(b[10:12], checksum(b[0:20]))

	udpLen := 8 + len(payload)
	binary.BigEndian.PutUint16(b[20:22], srcPort)
	binary.BigEndian.PutUint16(b[22:24], dstPort)
	binary.BigEndian.PutUint16(b[24:26], uint16(udpLen))
	copy(b[28:], payload)

	pseudo := pseudoHeaderChecksum(ProtoUDP, srcBytes[:], dstBytes[:], uint16(udpLen))
	csum := checksumWithPseudo(b[20:totalLen], pseudo)
	if csum == 0 {
		csum = 0xFFFF
	}
	binary.BigEndian.PutUint16(b[26:28], csum)

	return b
}

func BuildIPv4TCP(srcIP, dstIP netip.Addr, srcPort, dstPort uint16, seqNum, ackNum uint32, flags uint8, window uint16, payload []byte) []byte {
	srcBytes := toIPv4(srcIP)
	dstBytes := toIPv4(dstIP)

	totalLen := 20 + 20 + len(payload)
	b := make([]byte, totalLen)

	b[0] = 0x45
	b[1] = 0
	binary.BigEndian.PutUint16(b[2:4], uint16(totalLen))
	binary.BigEndian.PutUint16(b[4:6], 0)
	binary.BigEndian.PutUint16(b[6:8], 0x4000) // DF flag
	b[8] = 64
	b[9] = ProtoTCP
	copy(b[12:16], srcBytes[:])
	copy(b[16:20], dstBytes[:])
	binary.BigEndian.PutUint16(b[10:12], checksum(b[0:20]))

	binary.BigEndian.PutUint16(b[20:22], srcPort)
	binary.BigEndian.PutUint16(b[22:24], dstPort)
	binary.BigEndian.PutUint32(b[24:28], seqNum)
	binary.BigEndian.PutUint32(b[28:32], ackNum)
	b[32] = 0x50 // 5 words = 20 bytes
	b[33] = flags
	if window == 0 {
		window = 65535
	}
	binary.BigEndian.PutUint16(b[34:36], window)
	copy(b[40:], payload)

	tcpLen := 20 + len(payload)
	pseudo := pseudoHeaderChecksum(ProtoTCP, srcBytes[:], dstBytes[:], uint16(tcpLen))
	csum := checksumWithPseudo(b[20:totalLen], pseudo)
	if csum == 0 {
		csum = 0xFFFF
	}
	binary.BigEndian.PutUint16(b[36:38], csum)

	return b
}

// BuildIPv4TCPSynAck создает пакет TCP SYN-ACK с опцией MSS (Maximum Segment Size).
func BuildIPv4TCPSynAck(srcIP, dstIP netip.Addr, srcPort, dstPort uint16, seqNum, ackNum uint32, mss uint16) []byte {
	srcBytes := toIPv4(srcIP)
	dstBytes := toIPv4(dstIP)

	// IP hdr: 20 bytes, TCP hdr: 24 bytes (20 + 4 MSS option)
	totalLen := 20 + 24
	b := make([]byte, totalLen)

	b[0] = 0x45
	b[1] = 0
	binary.BigEndian.PutUint16(b[2:4], uint16(totalLen))
	binary.BigEndian.PutUint16(b[4:6], 0)
	binary.BigEndian.PutUint16(b[6:8], 0x4000)
	b[8] = 64
	b[9] = ProtoTCP
	copy(b[12:16], srcBytes[:])
	copy(b[16:20], dstBytes[:])
	binary.BigEndian.PutUint16(b[10:12], checksum(b[0:20]))

	binary.BigEndian.PutUint16(b[20:22], srcPort)
	binary.BigEndian.PutUint16(b[22:24], dstPort)
	binary.BigEndian.PutUint32(b[24:28], seqNum)
	binary.BigEndian.PutUint32(b[28:32], ackNum)
	b[32] = 0x60 // 6 words = 24 bytes
	b[33] = TCPFlagSYN | TCPFlagACK
	binary.BigEndian.PutUint16(b[34:36], 65535)

	// MSS Option: Kind=2, Length=4, Value=mss
	b[40] = 0x02
	b[41] = 0x04
	binary.BigEndian.PutUint16(b[42:44], mss)

	pseudo := pseudoHeaderChecksum(ProtoTCP, srcBytes[:], dstBytes[:], 24)
	csum := checksumWithPseudo(b[20:totalLen], pseudo)
	if csum == 0 {
		csum = 0xFFFF
	}
	binary.BigEndian.PutUint16(b[36:38], csum)

	return b
}

func checksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i < len(b)-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i : i+2]))
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for (sum >> 16) > 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}

func pseudoHeaderChecksum(protocol uint8, srcIP, dstIP []byte, length uint16) uint32 {
	var sum uint32
	for i := 0; i < len(srcIP); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(srcIP[i : i+2]))
	}
	for i := 0; i < len(dstIP); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(dstIP[i : i+2]))
	}
	sum += uint32(protocol)
	sum += uint32(length)
	return sum
}

func checksumWithPseudo(b []byte, pseudoSum uint32) uint16 {
	sum := pseudoSum
	for i := 0; i < len(b)-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i : i+2]))
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for (sum >> 16) > 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}
