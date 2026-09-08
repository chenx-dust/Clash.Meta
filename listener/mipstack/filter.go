package mipstack

import (
	"encoding/binary"
	"net/netip"

	tun "github.com/metacubex/sing-tun"
)

func (s *Stack) deliver(packet []byte) {
	if s.ctx.Err() != nil {
		return
	}
	source, destination, protocol, ok := packetAddresses(packet)
	if !ok {
		return
	}
	// Match sing-tun's LinkEndpointFilter, including reflecting non-unicast
	// packets unchanged rather than offering them to protocol forwarders.
	if destination == tun.BroadcastAddr(s.options.TunOptions.Inet4Address) || !destination.IsGlobalUnicast() {
		if err := s.writePacket(packet); err != nil {
			s.fail(err)
		}
		return
	}
	if protocol == 6 {
		addresses := s.options.TunOptions.Inet4LoopbackAddress
		if destination.Is6() {
			addresses = s.options.TunOptions.Inet6LoopbackAddress
		}
		for _, address := range addresses {
			if address != destination {
				continue
			}
			response := append([]byte(nil), packet...)
			if destination.Is4() {
				copy(response[12:16], destination.AsSlice())
				copy(response[16:20], source.AsSlice())
			} else {
				copy(response[8:24], destination.AsSlice())
				copy(response[24:40], source.AsSlice())
			}
			// Swapping the addresses preserves both the IP checksum and the
			// TCP pseudo-header sum, also for fragments and extension headers.
			if err := s.writePacket(response); err != nil {
				s.fail(err)
			}
			return
		}
	}
	// Invalid packet errors are local to the datagram, not fatal device errors.
	_, _ = s.stack.Write([][]byte{packet}, 0)
}

func packetAddresses(packet []byte) (source, destination netip.Addr, protocol byte, ok bool) {
	if len(packet) == 0 {
		return
	}
	switch packet[0] >> 4 {
	case 4:
		if len(packet) < 20 {
			return
		}
		headerLen := int(packet[0]&15) * 4
		total := int(binary.BigEndian.Uint16(packet[2:4]))
		if headerLen < 20 || total < headerLen || total > len(packet) {
			return
		}
		source = netip.AddrFrom4([4]byte(packet[12:16]))
		destination = netip.AddrFrom4([4]byte(packet[16:20]))
		return source, destination, packet[9], true
	case 6:
		if len(packet) < 40 {
			return
		}
		total := 40 + int(binary.BigEndian.Uint16(packet[4:6]))
		if total > len(packet) {
			return
		}
		source = netip.AddrFrom16([16]byte(packet[8:24]))
		destination = netip.AddrFrom16([16]byte(packet[24:40]))
		protocol = packet[6]
		for offset := 40; ; {
			var size int
			switch protocol {
			case 0, 43, 60:
				if offset+2 > total {
					return source, destination, 0, false
				}
				size = (int(packet[offset+1]) + 1) * 8
			case 44:
				size = 8
			case 51:
				if offset+2 > total {
					return source, destination, 0, false
				}
				size = (int(packet[offset+1]) + 2) * 4
			default:
				return source, destination, protocol, true
			}
			if offset+size > total {
				return source, destination, 0, false
			}
			next := packet[offset]
			if protocol == 44 && binary.BigEndian.Uint16(packet[offset+2:offset+4])&0xfff8 != 0 {
				return source, destination, next, true
			}
			protocol = next
			offset += size
		}
	}
	return
}
