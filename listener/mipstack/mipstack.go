package mipstack

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	mips "github.com/metacubex/mipstack"
	tun "github.com/metacubex/sing-tun"
	"github.com/metacubex/sing/common/buf"
	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"
)

var _ tun.Stack = (*Stack)(nil)

type Stack struct {
	options tun.StackOptions
	ctx     context.Context
	cancel  context.CancelFunc
	mu      sync.Mutex
	writeMu sync.Mutex
	stack   *mips.Stack
	closed  bool
	icmp    chan *mips.ICMPForwarderResponder
}

func New(options tun.StackOptions) (tun.Stack, error) {
	if options.Tun == nil || options.Handler == nil {
		return nil, errors.New("mips: missing TUN or handler")
	}
	if len(options.TunOptions.Inet4Address) == 0 && len(options.TunOptions.Inet6Address) == 0 {
		return nil, errors.New("mips: missing interface address")
	}
	if options.TunOptions.MTU < 68 || options.TunOptions.MTU > 65535 {
		return nil, errors.New("mips: MTU must be between 68 and 65535")
	}
	if options.Context == nil {
		options.Context = context.Background()
	}
	if options.ICMPTimeout <= 0 {
		options.ICMPTimeout = 30 * time.Second
	}
	ctx, cancel := context.WithCancel(options.Context)
	return &Stack{options: options, ctx: ctx, cancel: cancel, icmp: make(chan *mips.ICMPForwarderResponder, 64)}, nil
}

func (s *Stack) config() mips.Config {
	// Interface addresses belong to the host. Registering them here would
	// route replies into MIPS' internal loopback instead of back to the TUN.
	var addresses []netip.Prefix
	if len(s.options.TunOptions.Inet4Address) != 0 {
		addresses = append(addresses, netip.MustParsePrefix("127.0.0.1/32"))
	}
	if len(s.options.TunOptions.Inet6Address) != 0 {
		addresses = append(addresses, netip.MustParsePrefix("::1/128"))
	}
	return mips.Config{LocalAddresses: addresses, Promiscuous: true, MTU: s.options.TunOptions.MTU,
		TCP: mips.TCPSocketDefaults{ReceiveBuffer: 20 * 1024, MaximumReceiveBuffer: 20 * 1024,
			SendBuffer: 20 * 1024, MaximumSendBuffer: 20 * 1024, KeepAlive: true,
			KeepAliveConfig: mips.KeepAliveConfig{Idle: 15 * time.Second, Interval: 15 * time.Second}}}
}

func (s *Stack) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.ctx.Err() != nil {
		return net.ErrClosed
	}
	if s.stack != nil {
		return nil
	}
	stack, err := mips.New(s.config())
	if err != nil {
		return err
	}
	if _, err = mips.NewTCPForwarder(stack, mips.TCPForwarderOptions{}, s.forwardTCP); err == nil {
		_, err = mips.NewUDPForwarder(stack, mips.UDPForwarderOptions{}, s.forwardUDP)
	}
	if err == nil {
		_, err = mips.NewICMPForwarder(stack, mips.ICMPForwarderOptions{}, s.forwardICMP)
	}
	if err == nil {
		err = stack.Start()
	}
	if err != nil {
		_ = stack.Close()
		return err
	}
	s.stack = stack
	go s.loopICMP()
	go s.readLoop()
	go s.writeLoop()
	go func() { <-s.ctx.Done(); _ = s.Close() }()
	return nil
}

func (s *Stack) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	s.cancel()
	stack := s.stack
	s.mu.Unlock()
	// The listener owns TUN.Close. Do not wait for its blocking Read here.
	if stack != nil {
		return stack.Close()
	}
	return nil
}

func (s *Stack) fail(err error) {
	if s.ctx.Err() == nil {
		if s.options.Logger != nil {
			s.options.Logger.Error(fmt.Errorf("mips: TUN I/O: %w", err))
		}
		_ = s.Close()
	}
}

func (s *Stack) forwardTCP(request *mips.TCPForwarderRequest) {
	flow := request.Flow()
	conn, err := request.Accept(s.ctx)
	if err != nil {
		return
	}
	metadata := M.Metadata{Source: M.SocksaddrFromNetIP(flow.Source), Destination: M.SocksaddrFromNetIP(flow.Destination)}
	go func() {
		if err := s.options.Handler.NewConnection(s.ctx, conn, metadata); err != nil {
			_ = conn.SetLinger(0)
			_ = conn.Close()
		}
	}()
}

func (s *Stack) forwardUDP(request *mips.UDPForwarderRequest) {
	flow := request.Flow()
	buffer := buf.NewSize(len(request.Payload()))
	_, _ = buffer.Write(request.Payload())
	responder, err := request.DetachForReplies()
	if err != nil {
		buffer.Release()
		return
	}
	s.options.Handler.NewPacket(s.ctx, flow.Source, buffer,
		M.Metadata{Source: M.SocksaddrFromNetIP(flow.Source), Destination: M.SocksaddrFromNetIP(flow.Destination)},
		func(N.PacketConn) N.PacketWriter { return &udpWriter{responder} })
}

type udpWriter struct{ responder *mips.UDPForwarderResponder }

func (w *udpWriter) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	defer buffer.Release()
	if !destination.IsIP() {
		return errors.New("mips: invalid UDP response address")
	}
	_, err := w.responder.ReplyFrom(buffer.Bytes(), destination.AddrPort())
	return err
}
