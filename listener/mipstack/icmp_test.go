package mipstack

import (
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"

	tun "github.com/metacubex/sing-tun"
	"github.com/metacubex/sing/common/buf"
)

type echoDestination struct {
	writer tun.DirectRouteContext
	closed chan struct{}
	once   sync.Once
}

func (d *echoDestination) IsClosed() bool {
	select {
	case <-d.closed:
		return true
	default:
		return false
	}
}
func (d *echoDestination) Close() error { d.once.Do(func() { close(d.closed) }); return nil }
func (d *echoDestination) WritePacket(b *buf.Buffer) error {
	defer b.Release()
	source, target, protocol, _ := packetAddresses(b.Bytes())
	offset := 20
	kind := byte(0)
	if source.Is6() {
		offset = 40
		kind = 129
	}
	payload := append([]byte(nil), b.Bytes()[offset:]...)
	payload[0] = kind
	payload[2], payload[3] = 0, 0
	packet := transportPacket(target, source, protocol, payload)
	go func() { _ = d.writer.WritePacket(packet) }()
	return nil
}

func TestICMPDirectSessionLifecycle(t *testing.T) {
	for _, mode := range []string{"expire", "close"} {
		t.Run(mode, func(t *testing.T) {
			d := newMemoryTun()
			created := make(chan *echoDestination, 4)
			h := &testHandler{prepare: func(writer tun.DirectRouteContext) (tun.DirectRouteDestination, error) {
				destination := &echoDestination{writer: writer, closed: make(chan struct{})}
				created <- destination
				return destination, nil
			}}
			s := testStack(t, d, h, func(o *tun.StackOptions) { o.ICMPTimeout = 200 * time.Millisecond })
			source, target := netip.MustParseAddr("198.18.0.1"), netip.MustParseAddr("8.8.8.8")
			for i := 0; i < 2; i++ {
				d.in <- transportPacket(source, target, 1, []byte{8, 0, 0, 0, 0, 1, 0, byte(i)})
				p := readPacket(t, d)
				if p[20] != 0 || p[len(p)-1] != byte(i) {
					t.Fatalf("invalid asynchronous ping response %x", p)
				}
			}
			var destination *echoDestination
			select {
			case destination = <-created:
			case <-time.After(time.Second):
				t.Fatal("missing ICMP destination")
			}
			select {
			case <-created:
				t.Fatal("ICMP session not reused")
			default:
			}
			if mode == "close" {
				_ = s.Close()
			}
			select {
			case <-destination.closed:
			case <-time.After(time.Second):
				t.Fatal("ICMP destination leaked")
			}
		})
	}
}

func TestICMPPolicy(t *testing.T) {
	for _, policy := range []string{"drop", "reset", "fallback"} {
		t.Run(policy, func(t *testing.T) {
			d := newMemoryTun()
			called := make(chan struct{}, 1)
			h := &testHandler{prepare: func(tun.DirectRouteContext) (tun.DirectRouteDestination, error) {
				called <- struct{}{}
				switch policy {
				case "drop":
					return nil, tun.ErrDrop
				case "reset":
					return nil, tun.ErrReset
				default:
					return nil, errors.New("dial failed")
				}
			}}
			testStack(t, d, h, nil)
			d.in <- transportPacket(netip.MustParseAddr("198.18.0.1"), netip.MustParseAddr("8.8.8.8"), 1, []byte{8, 0, 0, 0, 0, 1, 0, 1})
			select {
			case <-called:
			case <-time.After(time.Second):
				t.Fatal("policy not called")
			}
			if policy == "drop" {
				select {
				case p := <-d.out:
					t.Fatalf("drop emitted %x", p)
				case <-time.After(50 * time.Millisecond):
				}
				return
			}
			p := readPacket(t, d)
			want := byte(0)
			if policy == "reset" {
				want = 3
			}
			if p[20] != want {
				t.Fatalf("wrong ICMP policy response %x", p)
			}
		})
	}
}
