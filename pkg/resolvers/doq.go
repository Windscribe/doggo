package resolvers

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"github.com/lucas-clemente/quic-go"
	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

// DOQResolver represents the config options for setting up a DOQ based resolver.
type DOQResolver struct {
	tls             *tls.Config
	server          string
	resolverOptions Options
}

// NewDOQResolver accepts a nameserver address and configures a DOQ based resolver.
func NewDOQResolver(server string, resolverOpts Options) (Resolver, error) {
	return &DOQResolver{
		tls: &tls.Config{
			NextProtos: []string{"doq"},
		},
		server:          server,
		resolverOptions: resolverOpts,
	}, nil
}

// Lookup takes a dns.Question and sends them to DNS Server.
// It parses the Response from the server in a custom output format.
func (r *DOQResolver) Lookup(question dns.Question) (Response, error) {
	var (
		rsp      Response
		messages = prepareMessages(question, r.resolverOptions.Ndots, r.resolverOptions.SearchList)
	)

	session, err := quic.DialAddr(r.server, r.tls, nil)
	if err != nil {
		return rsp, err
	}
	defer session.CloseWithError(quic.ApplicationErrorCode(quic.NoError), "")

	for _, msg := range messages {
		r.resolverOptions.Logger.WithFields(logrus.Fields{
			"domain":     msg.Question[0].Name,
			"ndots":      r.resolverOptions.Ndots,
			"nameserver": r.server,
		}).Debug("Attempting to resolve")

		// ref: https://www.rfc-editor.org/rfc/rfc9250.html#name-dns-message-ids
		msg.Id = 0

		// get the DNS Message in wire format.
		var b []byte
		b, err = msg.Pack()
		if err != nil {
			return rsp, err
		}
		now := time.Now()

		var stream quic.Stream
		stream, err = session.OpenStream()
		if err != nil {
			return rsp, err
		}

		var msgLen = uint16(len(b))
		var msgLenBytes = []byte{byte(msgLen >> 8), byte(msgLen & 0xFF)}
		_, err = stream.Write(msgLenBytes)
		if err != nil {
			return rsp, err
		}
		// Make a QUIC request to the DNS server with the DNS message as wire format bytes in the body.
		_, err = stream.Write(b)
		if err != nil {
			return rsp, err
		}

		err = stream.SetDeadline(time.Now().Add(r.resolverOptions.Timeout))
		if err != nil {
			return rsp, err
		}

		var buf []byte
		buf, err = io.ReadAll(stream)
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				return rsp, fmt.Errorf("timeout")
			}
			return rsp, err
		}
		rtt := time.Since(now)

		_ = stream.Close()

		packetLen := binary.BigEndian.Uint16(buf[:2])
		if packetLen != uint16(len(buf[2:])) {
			return rsp, fmt.Errorf("packet length mismatch")
		}
		err = msg.Unpack(buf[2:])
		if err != nil {
			return rsp, err
		}
		// pack questions in output.
		for _, q := range msg.Question {
			ques := Question{
				Name:  q.Name,
				Class: dns.ClassToString[q.Qclass],
				Type:  dns.TypeToString[q.Qtype],
			}
			rsp.Questions = append(rsp.Questions, ques)
		}
		// get the authorities and answers.
		output := parseMessage(&msg, rtt, r.server)
		rsp.Authorities = output.Authorities
		rsp.Answers = output.Answers

		if len(output.Answers) > 0 {
			// stop iterating the searchlist.
			break
		}
	}
	return rsp, nil
}

func (r *DOQResolver) SetTLSConfig(tlsCfg *tls.Config) {
	r.tls = tlsCfg
}

// Lookup1 likes Lookup, but return a list of dns.Msg instead.
func (r *DOQResolver) Lookup1(question dns.Question) ([]dns.Msg, error) {
	messages := prepareMessages(question, r.resolverOptions.Ndots, r.resolverOptions.SearchList)
	resp := make([]dns.Msg, 0, len(messages))

	network := "udp"
	if isIPv6(r.server) || question.Qtype == dns.TypeAAAA {
		network = "udp6"
	}
	udpAddr, err := net.ResolveUDPAddr(network, r.server)
	if err != nil {
		return nil, err
	}
	udpConn, err := net.ListenPacket(network, "")
	if err != nil {
		return nil, err
	}
	defer udpConn.Close()

	session, err := quic.Dial(udpConn, udpAddr, r.server, r.tls, nil)
	if err != nil {
		return nil, err
	}
	defer session.CloseWithError(quic.ApplicationErrorCode(quic.NoError), "")

	for _, msg := range messages {
		// ref: https://www.rfc-editor.org/rfc/rfc9250.html#name-dns-message-ids
		msg.Id = 0

		// get the DNS Message in wire format.
		var b []byte
		b, err = msg.Pack()
		if err != nil {
			return nil, err
		}

		var stream quic.Stream
		stream, err = session.OpenStreamSync(context.Background())
		if err != nil {
			return nil, err
		}

		var msgLen = uint16(len(b))
		var msgLenBytes = []byte{byte(msgLen >> 8), byte(msgLen & 0xFF)}
		_, err = stream.Write(msgLenBytes)
		if err != nil {
			return nil, err
		}
		// Make a QUIC request to the DNS server with the DNS message as wire format bytes in the body.
		_, err = stream.Write(b)
		if err != nil {
			return nil, err
		}

		err = stream.SetDeadline(time.Now().Add(r.resolverOptions.Timeout))
		if err != nil {
			return nil, err
		}

		buf, err := io.ReadAll(stream)
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				return nil, fmt.Errorf("timeout")
			}
			return nil, err
		}
		// io.ReadAll hide the io.EOF error returned by quic-go server.
		// Once we figure out why quic-go server sends io.EOF after running
		// for a long time, we can have a better way to handle this. For now,
		// make sure io.EOF error returned, so the caller can handle it cleanly.
		if len(buf) == 0 {
			return nil, io.EOF
		}
		_ = stream.Close()

		packetLen := binary.BigEndian.Uint16(buf[:2])
		if packetLen != uint16(len(buf[2:])) {
			return nil, fmt.Errorf("packet length mismatch,got: %d, want: %d", packetLen, len(buf[2:]))
		}
		if err := msg.Unpack(buf[2:]); err != nil {
			return nil, err
		}
		resp = append(resp, msg)
	}
	return resp, nil
}

func isIPv6(ip string) bool {
	justIP, _, err := net.SplitHostPort(ip)
	if err != nil {
		justIP = ip
	}
	parsedIP := net.ParseIP(justIP)
	return parsedIP != nil && parsedIP.To4() == nil && parsedIP.To16() != nil
}
