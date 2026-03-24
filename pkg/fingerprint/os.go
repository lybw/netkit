// Package fingerprint provides OS detection via TCP/IP stack analysis.
package fingerprint

import (
	"fmt"
	"net"
	"time"
)

// OSGuess represents an OS detection result.
type OSGuess struct {
	OS         string
	Confidence int // 0-100
	TTL        int
	Method     string
}

// DetectByTTL performs basic OS detection by analyzing the initial TTL value.
// This is a passive/lightweight approach based on the ICMP or TCP response TTL.
func DetectByTTL(host string, timeout time.Duration) (*OSGuess, error) {
	if timeout <= 0 {
		timeout = 3 * time.Second
	}

	// Try TCP connection to common ports to get TTL
	ports := []int{80, 443, 22, 445, 135}
	for _, port := range ports {
		addr := fmt.Sprintf("%s:%d", host, port)
		conn, err := net.DialTimeout("tcp", addr, timeout)
		if err != nil {
			continue
		}

		// Get TTL from the TCP connection
		ttl, err := getTTL(conn)
		conn.Close()
		if err != nil {
			continue
		}

		guess := classifyByTTL(ttl)
		return guess, nil
	}

	return nil, fmt.Errorf("could not connect to %s on any common port", host)
}

// classifyByTTL maps observed TTL to likely OS family.
// Default TTL values:
//   - Linux/Android: 64
//   - Windows: 128
//   - macOS/iOS: 64
//   - Cisco/Network devices: 255
//   - Solaris/AIX: 254
func classifyByTTL(ttl int) *OSGuess {
	g := &OSGuess{
		TTL:    ttl,
		Method: "ttl",
	}

	switch {
	case ttl <= 32:
		g.OS = "Unknown (very low TTL, possibly custom)"
		g.Confidence = 20
	case ttl <= 64:
		g.OS = "Linux/macOS/Unix"
		g.Confidence = 60
	case ttl <= 128:
		g.OS = "Windows"
		g.Confidence = 70
	case ttl <= 254:
		g.OS = "Solaris/AIX"
		g.Confidence = 40
	case ttl == 255:
		g.OS = "Network Device (Cisco/Router/Switch)"
		g.Confidence = 50
	default:
		g.OS = "Unknown"
		g.Confidence = 10
	}

	return g
}

// DeviceType attempts to classify the device type based on open ports.
func DeviceType(openPorts []int) string {
	portSet := make(map[int]bool)
	for _, p := range openPorts {
		portSet[p] = true
	}

	// Network infrastructure
	if portSet[161] || portSet[162] { // SNMP
		return "Network Device"
	}
	if portSet[23] && !portSet[80] { // Telnet only
		return "Network Device"
	}

	// Printers
	if portSet[9100] || portSet[515] || portSet[631] {
		return "Printer"
	}

	// Cameras / DVR / NVR
	if portSet[554] || portSet[8554] { // RTSP
		return "Camera/DVR"
	}

	// Database servers
	if portSet[3306] || portSet[5432] || portSet[1433] || portSet[1521] || portSet[27017] || portSet[6379] {
		return "Database Server"
	}

	// Web servers
	if portSet[80] || portSet[443] || portSet[8080] || portSet[8443] {
		if portSet[22] {
			return "Server"
		}
		return "Web Server"
	}

	// Windows workstation
	if portSet[135] && portSet[445] {
		if portSet[3389] {
			return "Windows Server"
		}
		return "Windows Workstation"
	}

	// SSH-only (Linux server)
	if portSet[22] && len(openPorts) <= 3 {
		return "Linux Server"
	}

	return "Unknown"
}
