package mipstack

import (
	"errors"
	"time"

	mips "github.com/metacubex/mipstack"
	tun "github.com/metacubex/sing-tun"
	"github.com/metacubex/sing/common/buf"
	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"
)

func (s *Stack) forwardICMP(request *mips.ICMPForwarderRequest) {
	message := request.Message()
	if message.Code != 0 || (message.Source.Is4() && message.Type != 8) || (message.Source.Is6() && message.Type != 128) {
		request.Drop()
		return
	}
	responder, err := request.Detach()
	if err != nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ctx.Err() != nil {
		responder.Drop()
		return
	}
	// Preparing a ping destination may block. Never block Stack.Write waiting
	// for network operations, and bound retained request storage.
	select {
	case s.icmp <- responder:
	default:
		responder.Drop()
	}
}

type icmpWriter struct{ responder *mips.ICMPForwarderResponder }

func (w icmpWriter) WritePacket(packet []byte) error { return w.responder.ReplyIPPacket(packet) }

type icmpSession struct {
	destination tun.DirectRouteDestination
	lastUsed    time.Time
}

func (s *Stack) loopICMP() {
	sessions := make(map[tun.DirectRouteSession]icmpSession)
	remove := func(key tun.DirectRouteSession) {
		if destination := sessions[key].destination; destination != nil {
			_ = destination.Close()
		}
		delete(sessions, key)
	}
	defer func() {
		for key := range sessions {
			remove(key)
		}
		for {
			select {
			case r := <-s.icmp:
				r.Drop()
			default:
				return
			}
		}
	}()
	interval := s.options.ICMPTimeout
	if interval > time.Second {
		interval = time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case now := <-ticker.C:
			for key, session := range sessions {
				if now.Sub(session.lastUsed) >= s.options.ICMPTimeout || (session.destination != nil && session.destination.IsClosed()) {
					remove(key)
				}
			}
		case request := <-s.icmp:
			if s.ctx.Err() != nil {
				request.Drop()
				return
			}
			message := request.Message()
			key := tun.DirectRouteSession{Source: message.Source, Destination: message.Destination}
			session, exists := sessions[key]
			if exists && (time.Since(session.lastUsed) >= s.options.ICMPTimeout || (session.destination != nil && session.destination.IsClosed())) {
				remove(key)
				exists = false
			}
			if !exists {
				if len(sessions) >= 1024 {
					var oldest tun.DirectRouteSession
					var oldestTime time.Time
					for k, v := range sessions {
						if oldestTime.IsZero() || v.lastUsed.Before(oldestTime) {
							oldest, oldestTime = k, v.lastUsed
						}
					}
					remove(oldest)
				}
				destination, err := s.options.Handler.PrepareConnection(N.NetworkICMP,
					M.SocksaddrFrom(message.Source, 0), M.SocksaddrFrom(message.Destination, 0), icmpWriter{request}, s.options.ICMPTimeout)
				if errors.Is(err, tun.ErrDrop) {
					request.Drop()
					continue
				}
				if errors.Is(err, tun.ErrReset) {
					_ = request.Reject()
					continue
				}
				if err != nil {
					_ = request.ReplyEcho()
					request.Drop()
					continue
				}
				session = icmpSession{destination: destination}
			}
			session.lastUsed = time.Now()
			sessions[key] = session
			if s.ctx.Err() != nil {
				request.Drop()
				return
			}
			if session.destination == nil {
				_ = request.ReplyEcho()
				request.Drop()
			} else {
				packet := request.IPPacket()
				buffer := buf.NewSize(len(packet))
				_, _ = buffer.Write(packet)
				_ = session.destination.WritePacket(buffer)
				// The first responder belongs to the session's asynchronous writer.
				// Do not mutate its snapshot while that writer may be replying.
				if exists {
					request.Drop()
				}
			}
		}
	}
}
