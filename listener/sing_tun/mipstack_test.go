package sing_tun

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/resolver"
	"github.com/metacubex/mihomo/listener/mipstack"

	mips "github.com/metacubex/mipstack"
	tun "github.com/metacubex/sing-tun"
	D "github.com/miekg/dns"
)

// A second stack represents the host, so the test exercises real TCP framing,
// UDP packets and the DNS handler without installing a privileged TUN device.
type mipstackPeer struct{ client *mips.Stack }

func (p mipstackPeer) Read(buffer []byte) (int, error) {
	var sizes [1]int
	n, err := p.client.Read([][]byte{buffer}, sizes[:], 0)
	if n > 0 {
		return sizes[0], err
	}
	return 0, err
}
func (p mipstackPeer) Write(buffer []byte) (int, error) {
	n, err := p.client.Write([][]byte{buffer}, 0)
	if n > 0 {
		return len(buffer), err
	}
	return 0, err
}
func (p mipstackPeer) Close() error { return p.client.Close() }

type mipstackDNSService struct{}

func (mipstackDNSService) ServeMsg(_ context.Context, query *D.Msg) (*D.Msg, error) {
	reply := new(D.Msg)
	reply.SetReply(query)
	reply.Answer = []D.RR{&D.A{Hdr: D.RR_Header{Name: query.Question[0].Name, Rrtype: D.TypeA, Class: D.ClassINET, Ttl: 60}, A: net.IPv4(192, 0, 2, 1)}}
	return reply, nil
}

func TestMipsDNSHijack(t *testing.T) {
	previous := resolver.DefaultService
	resolver.DefaultService = mipstackDNSService{}
	defer func() { resolver.DefaultService = previous }()
	for _, family := range []string{"4", "6"} {
		for _, network := range []string{"udp", "tcp"} {
			t.Run(network+family, func(t *testing.T) {
				prefix := netip.MustParsePrefix("198.18.0.1/30")
				target := netip.MustParseAddrPort("8.8.8.8:53")
				if family == "6" {
					prefix = netip.MustParsePrefix("fd00::1/126")
					target = netip.MustParseAddrPort("[2001:4860:4860::8888]:53")
				}
				client, err := mips.New(mips.Config{LocalAddresses: []netip.Prefix{prefix}, MTU: 1500})
				if err != nil {
					t.Fatal(err)
				}
				defer client.Close()
				if err = client.Start(); err != nil {
					t.Fatal(err)
				}
				options := tun.Options{MTU: 1500}
				if family == "4" {
					options.Inet4Address = []netip.Prefix{prefix}
				} else {
					options.Inet6Address = []netip.Prefix{prefix}
				}
				handler := &ListenerHandler{DnsAddrPorts: []netip.AddrPort{netip.MustParseAddrPort("0.0.0.0:53")}}
				server, err := mipstack.New(tun.StackOptions{Context: context.Background(), Tun: mipstackPeer{client}, TunOptions: options, Handler: handler})
				if err != nil {
					t.Fatal(err)
				}
				defer server.Close()
				if err = server.Start(); err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				var conn net.Conn
				if network == "tcp" {
					conn, err = client.DialTCP(ctx, network+family, netip.AddrPortFrom(prefix.Addr(), 0), target)
				} else {
					conn, err = client.DialUDP(ctx, network+family, netip.AddrPortFrom(prefix.Addr(), 0), target)
				}
				if err != nil {
					t.Fatal(err)
				}
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
				query := new(D.Msg)
				query.SetQuestion("mips.test.", D.TypeA)
				payload, err := query.Pack()
				if err != nil {
					t.Fatal(err)
				}
				if network == "tcp" {
					framed := make([]byte, 2+len(payload))
					binary.BigEndian.PutUint16(framed, uint16(len(payload)))
					copy(framed[2:], payload)
					payload = framed
				}
				if _, err = conn.Write(payload); err != nil {
					t.Fatal(err)
				}
				response := make([]byte, 2048)
				var n int
				if network == "tcp" {
					var size uint16
					if err = binary.Read(conn, binary.BigEndian, &size); err != nil {
						t.Fatal(err)
					}
					n, err = io.ReadFull(conn, response[:int(size)])
				} else {
					n, err = conn.Read(response)
				}
				if err != nil {
					t.Fatal(err)
				}
				reply := new(D.Msg)
				if err = reply.Unpack(response[:n]); err != nil {
					t.Fatal(err)
				}
				if reply.Id != query.Id || !reply.Response || len(reply.Answer) != 1 || reply.Answer[0].(*D.A).A.String() != "192.0.2.1" {
					t.Fatalf("incorrect DNS reply: %s", reply)
				}
			})
		}
	}
}
