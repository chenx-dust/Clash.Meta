package mipstack

import (
	"io"

	tun "github.com/metacubex/sing-tun"
	"github.com/metacubex/sing/common/buf"
)

func packetBuffers(count, size int) [][]byte {
	buffers := make([][]byte, count)
	for i := range buffers {
		buffers[i] = make([]byte, size)
	}
	return buffers
}

func (s *Stack) readLoop() {
	device := s.options.Tun
	if linux, ok := device.(tun.LinuxTUN); ok && linux.FrontHeadroom() > 0 {
		buffers := packetBuffers(linux.BatchSize(), 65535+linux.FrontHeadroom())
		sizes := make([]int, len(buffers))
		for s.ctx.Err() == nil {
			n, err := linux.BatchRead(buffers, linux.FrontHeadroom(), sizes)
			for i := 0; i < n; i++ {
				s.deliver(buffers[i][linux.FrontHeadroom() : linux.FrontHeadroom()+sizes[i]])
			}
			if err != nil {
				s.fail(err)
				return
			}
		}
		return
	}
	if windows, ok := device.(tun.WinTun); ok {
		for s.ctx.Err() == nil {
			packet, release, err := windows.ReadPacket()
			if len(packet) > 0 {
				s.deliver(packet)
			}
			if release != nil {
				release()
			}
			if err != nil {
				s.fail(err)
				return
			}
		}
		return
	}
	if darwin, ok := device.(tun.DarwinTUN); ok && s.options.TunOptions.EXP_RecvMsgX {
		for s.ctx.Err() == nil {
			buffers, err := darwin.BatchRead()
			for _, buffer := range buffers {
				s.deliver(buffer.Bytes())
				buffer.Release()
			}
			if err != nil {
				s.fail(err)
				return
			}
		}
		return
	}
	buffer := make([]byte, 65535+4)
	for s.ctx.Err() == nil {
		n, err := device.Read(buffer)
		offset := 0
		if _, isDarwin := device.(tun.DarwinTUN); isDarwin {
			offset = 4
		}
		if n > offset {
			s.deliver(buffer[offset:n])
		}
		if err != nil {
			s.fail(err)
			return
		}
	}
}

func (s *Stack) writeLoop() {
	buffers := packetBuffers(s.stack.BatchSize(), int(s.options.TunOptions.MTU))
	sizes := make([]int, len(buffers))
	for s.ctx.Err() == nil {
		n, err := s.stack.Read(buffers, sizes, 0)
		for i := 0; i < n; i++ {
			if writeErr := s.writePacket(buffers[i][:sizes[i]]); writeErr != nil {
				s.fail(writeErr)
				return
			}
		}
		if err != nil {
			s.fail(err)
			return
		}
	}
}

// writePacket serializes stack output and packets reflected by the filter.
// Each platform adapter receives its own writable buffer and required header.
func (s *Stack) writePacket(packet []byte) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if err := s.ctx.Err(); err != nil {
		return err
	}
	// sing-tun only initializes the GRO tables used by BatchWrite with GSO.
	if linux, ok := s.options.Tun.(tun.LinuxTUN); ok && linux.FrontHeadroom() > 0 {
		offset := linux.FrontHeadroom()
		buffer := make([]byte, offset+len(packet))
		copy(buffer[offset:], packet)
		n, err := linux.BatchWrite([][]byte{buffer}, offset)
		// sing-tun returns bytes written, including the virtio header.
		if err == nil && n != len(buffer) {
			err = io.ErrShortWrite
		}
		return err
	}
	if darwin, ok := s.options.Tun.(tun.DarwinTUN); ok {
		buffer := buf.NewSize(len(packet))
		defer buffer.Release()
		_, _ = buffer.Write(packet)
		return darwin.BatchWrite([]*buf.Buffer{buffer})
	}
	n, err := s.options.Tun.Write(packet)
	if err == nil && n != len(packet) {
		err = io.ErrShortWrite
	}
	return err
}
