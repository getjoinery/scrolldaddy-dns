package upstream

import (
	"fmt"
	"time"

	"github.com/miekg/dns"
	"scrolldaddy-dns/internal/logger"
)

// Forward sends a DNS query to the primary upstream server, falling back to
// secondary on any error or timeout. Returns SERVFAIL-equivalent error if both fail.
func Forward(query *dns.Msg, primary, secondary string) (*dns.Msg, error) {
	client := &dns.Client{
		Net:     "udp",
		Timeout: 5 * time.Second,
	}

	resp, _, err := client.Exchange(query, primary)
	if err == nil && resp != nil {
		return resp, nil
	}

	logger.Warn("upstream timeout on %s (err: %v), trying %s", primary, err, secondary)

	resp, _, err = client.Exchange(query, secondary)
	if err == nil && resp != nil {
		return resp, nil
	}

	return nil, fmt.Errorf("both upstreams failed: %s, %s", primary, secondary)
}
