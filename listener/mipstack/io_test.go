package mipstack

import (
	"context"
	"errors"
	"io"
	"net/netip"
	"testing"
	"time"

	tun "github.com/metacubex/sing-tun"
	"github.com/metacubex/sing/common/buf"
	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"
)

type linuxTun struct {
	*memoryTun
	headroom int
}

func (d *linuxTun) FrontHeadroom() int      { return d.headroom }
func (d *linuxTun) BatchSize() int          { return 4 }
func (d *linuxTun) TXChecksumOffload() bool { return false }
func (d *linuxTun) BatchRead(buffers [][]byte, offset int, sizes []int) (int, error) {
	if d.headroom == 0 {
		return 0, errors.New("non-GSO device must use Read")
	}
	if offset != d.headroom {
		return 0, errors.New("wrong read headroom")
	}
	n, err := d.Read(buffers[0][offset:])
	sizes[0] = n
	if err != nil {
		return 0, err
	}
	return 1, nil
}
func (d *linuxTun) BatchWrite(buffers [][]byte, offset int) (int, error) {
	if d.headroom == 0 {
		return 0, errors.New("non-GSO device must use Write")
	}
	if offset != d.headroom {
		return 0, errors.New("wrong write headroom")
	}
	var total int
	for _, p := range buffers {
		n, err := d.Write(p[offset:])
		if err != nil {
			return total, err
		}
		total += n + offset
	}
	return total, nil
}

type windowsTun struct {
	*memoryTun
	released chan struct{}
}

func (d *windowsTun) ReadPacket() ([]byte, func(), error) {
	select {
	case p := <-d.in:
		return p, func() {
			for i := range p {
				p[i] = 0
			}
			d.released <- struct{}{}
		}, nil
	case <-d.done:
		return nil, nil, io.EOF
	}
}

type darwinTun struct{ *memoryTun }

func (d *darwinTun) Read(p []byte) (int, error) {
	n, err := d.memoryTun.Read(p[4:])
	if err != nil {
		return 0, err
	}
	copy(p[:4], []byte{0, 0, 0, 2})
	if p[4]>>4 == 6 {
		p[3] = 30
	}
	return n + 4, nil
}

func (d *darwinTun) BatchRead() ([]*buf.Buffer, error) {
	select {
	case p := <-d.in:
		b := buf.NewSize(len(p))
		_, _ = b.Write(p)
		return []*buf.Buffer{b}, nil
	case <-d.done:
		return nil, io.EOF
	}
}
func (d *darwinTun) BatchWrite(buffers []*buf.Buffer) error {
	for _, b := range buffers {
		if _, err := d.Write(b.Bytes()); err != nil {
			return err
		}
	}
	return nil
}

func TestPlatformPacketIO(t *testing.T) {
	for _, name := range []string{"linux", "linux-gso", "windows", "darwin", "darwin-raw"} {
		t.Run(name, func(t *testing.T) {
			memory := newMemoryTun()
			var device tun.Tun = memory
			var released chan struct{}
			switch name {
			case "linux":
				device = &linuxTun{memory, 0}
			case "linux-gso":
				device = &linuxTun{memory, 10}
			case "windows":
				released = make(chan struct{}, 1)
				device = &windowsTun{memory, released}
			case "darwin", "darwin-raw":
				device = &darwinTun{memory}
			}
			h := &testHandler{udp: func(_ context.Context, _ netip.AddrPort, b *buf.Buffer, m M.Metadata, init func(N.PacketConn) N.PacketWriter) {
				w := init(nil)
				go func() {
					if released != nil {
						<-released
					}
					_ = w.WritePacket(b, m.Destination)
				}()
			}}
			testStack(t, device, h, func(o *tun.StackOptions) { o.TunOptions.EXP_RecvMsgX = name != "darwin-raw" })
			memory.in <- udpPacket(netip.MustParseAddr("198.18.0.1"), netip.MustParseAddr("8.8.8.8"), 53, []byte("owned payload"))
			p := readPacket(t, memory)
			if string(p[28:]) != "owned payload" {
				t.Fatalf("buffer ownership violated: %x", p)
			}
		})
	}
}

type failedTun struct {
	*memoryTun
	readFailure bool
}

func (d *failedTun) Read(p []byte) (int, error) {
	if d.readFailure {
		return 0, io.ErrUnexpectedEOF
	}
	return d.memoryTun.Read(p)
}
func (d *failedTun) Write([]byte) (int, error) { return 0, io.ErrShortWrite }
func TestIOFailureStopsStack(t *testing.T) {
	for _, readFailure := range []bool{true, false} {
		t.Run(map[bool]string{true: "read", false: "write"}[readFailure], func(t *testing.T) {
			d := &failedTun{newMemoryTun(), readFailure}
			s := testStack(t, d, &testHandler{}, nil)
			if !readFailure {
				d.in <- udpPacket(netip.MustParseAddr("198.18.0.1"), netip.MustParseAddr("224.0.0.1"), 53, nil)
			}
			select {
			case <-s.ctx.Done():
			case <-time.After(time.Second):
				t.Fatal("I/O failure did not stop stack")
			}
		})
	}
}
