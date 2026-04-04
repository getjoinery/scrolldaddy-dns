package dot

import (
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
	"scrolldaddy-dns/internal/cache"
	"scrolldaddy-dns/internal/logger"
	"scrolldaddy-dns/internal/resolver"
)

// Server starts a DNS-over-TLS server on the given port.
// Device identification is via SNI subdomain: {uid}.{baseDomain}
// e.g. "a1b2c3d4.dns.scrolldaddy.app"
func Server(port int, certFile, keyFile, baseDomain string, res *resolver.Resolver, c *cache.Cache) error {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return fmt.Errorf("loading TLS cert/key: %w", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	addr := fmt.Sprintf(":%d", port)
	listener, err := tls.Listen("tcp", addr, tlsConfig)
	if err != nil {
		return fmt.Errorf("listening on %s: %w", addr, err)
	}
	defer listener.Close()

	logger.Info("DoT server listening on %s", addr)

	for {
		conn, err := listener.Accept()
		if err != nil {
			// Log but keep accepting
			logger.Warn("DoT accept error: %v", err)
			continue
		}
		go handleConn(conn, baseDomain, res, c)
	}
}

// handleConn manages a single DoT connection for its lifetime.
func handleConn(conn net.Conn, baseDomain string, res *resolver.Resolver, c *cache.Cache) {
	defer conn.Close()

	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return
	}

	// Set handshake deadline
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	if err := tlsConn.Handshake(); err != nil {
		logger.Debug("DoT handshake error from %s: %v", conn.RemoteAddr(), err)
		return
	}

	// Extract resolver UID from SNI subdomain
	sni := tlsConn.ConnectionState().ServerName
	uid := extractUID(sni, baseDomain)
	if uid == "" {
		logger.Debug("DoT: no valid UID in SNI %q from %s", sni, conn.RemoteAddr())
		return
	}

	// Clear deadline for query loop
	conn.SetDeadline(time.Time{})

	// Handle DNS queries in a loop (TCP connections can be reused)
	for {
		msg, err := readTCPMessage(conn)
		if err != nil {
			if err != io.EOF {
				logger.Debug("DoT read error from %s: %v", conn.RemoteAddr(), err)
			}
			return
		}

		var query dns.Msg
		if err := query.Unpack(msg); err != nil {
			logger.Debug("DoT unpack error from %s: %v", conn.RemoteAddr(), err)
			return
		}

		c.RecordQuery(uid)
		result := res.Resolve(uid, &query)

		packed, err := result.DNSResponse.Pack()
		if err != nil {
			logger.Warn("DoT pack error: %v", err)
			return
		}

		if err := writeTCPMessage(conn, packed); err != nil {
			return
		}
	}
}

// extractUID strips the baseDomain suffix from an SNI to get the resolver UID.
// e.g. "a1b2c3d4.dns.scrolldaddy.app" with baseDomain "dns.scrolldaddy.app" → "a1b2c3d4"
func extractUID(sni, baseDomain string) string {
	suffix := "." + baseDomain
	if !strings.HasSuffix(sni, suffix) {
		return ""
	}
	uid := strings.TrimSuffix(sni, suffix)
	// Validate: must be exactly 32 lowercase hex chars
	if len(uid) != 32 {
		return ""
	}
	for _, c := range uid {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return ""
		}
	}
	return uid
}

// readTCPMessage reads one DNS message from a TCP connection (2-byte length prefix).
func readTCPMessage(conn net.Conn) ([]byte, error) {
	var msgLen uint16
	if err := binary.Read(conn, binary.BigEndian, &msgLen); err != nil {
		return nil, err
	}
	if msgLen == 0 {
		return nil, fmt.Errorf("zero-length DNS message")
	}
	buf := make([]byte, msgLen)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// writeTCPMessage writes one DNS message to a TCP connection (2-byte length prefix).
func writeTCPMessage(conn net.Conn, data []byte) error {
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(data)))
	if _, err := conn.Write(lenBuf[:]); err != nil {
		return err
	}
	_, err := conn.Write(data)
	return err
}
