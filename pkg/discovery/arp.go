// Package discovery provides LAN device discovery via ARP scanning.
package discovery

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"
)

// Device represents a discovered network device.
type Device struct {
	IP       string
	MAC      string
	Hostname string
}

// ARP discovers devices on a subnet by pinging all addresses then reading the ARP table.
// cidr example: "192.168.1.0/24"
func ARP(ctx context.Context, cidr string) ([]Device, error) {
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR %q: %w", cidr, err)
	}

	// Generate all host IPs in the subnet
	var ips []string
	for addr := ip.Mask(ipNet.Mask); ipNet.Contains(addr); incIP(addr) {
		ips = append(ips, addr.String())
	}
	// Remove network and broadcast addresses for /24+
	if len(ips) > 2 {
		ips = ips[1 : len(ips)-1]
	}

	// Ping sweep to populate ARP table
	pingSweep(ctx, ips)

	// Read ARP table
	return readARPTable()
}

// pingSweep sends ICMP pings to all IPs concurrently to populate the ARP table.
func pingSweep(ctx context.Context, ips []string) {
	var wg sync.WaitGroup
	sem := make(chan struct{}, 50) // limit concurrency

	for _, ip := range ips {
		select {
		case <-ctx.Done():
			return
		default:
		}

		wg.Add(1)
		sem <- struct{}{}

		go func(addr string) {
			defer wg.Done()
			defer func() { <-sem }()

			pingOnce(ctx, addr)
		}(ip)
	}
	wg.Wait()
}

func pingOnce(ctx context.Context, ip string) {
	var cmd *exec.Cmd
	ctx, cancel := context.WithTimeout(ctx, 1*time.Second)
	defer cancel()

	switch runtime.GOOS {
	case "windows":
		cmd = exec.CommandContext(ctx, "ping", "-n", "1", "-w", "500", ip)
	default:
		cmd = exec.CommandContext(ctx, "ping", "-c", "1", "-W", "1", ip)
	}
	_ = cmd.Run() // we don't care about the result, just populating ARP
}

// readARPTable parses the OS ARP table.
func readARPTable() ([]Device, error) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("arp", "-a")
	default:
		cmd = exec.Command("arp", "-an")
	}

	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("arp command failed: %w", err)
	}

	return parseARPOutput(string(out), runtime.GOOS)
}

// parseARPOutput extracts IP/MAC pairs from arp command output.
func parseARPOutput(output string, goos string) ([]Device, error) {
	var devices []Device

	// Match IP and MAC patterns
	var macRe *regexp.Regexp
	if goos == "windows" {
		// Windows: "  192.168.1.1          00-0c-29-aa-bb-cc     dynamic"
		macRe = regexp.MustCompile(`(\d+\.\d+\.\d+\.\d+)\s+([\da-fA-F]{2}-[\da-fA-F]{2}-[\da-fA-F]{2}-[\da-fA-F]{2}-[\da-fA-F]{2}-[\da-fA-F]{2})`)
	} else {
		// Linux/macOS: "? (192.168.1.1) at 00:0c:29:aa:bb:cc [ether] on eth0"
		macRe = regexp.MustCompile(`\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([\da-fA-F]{2}:[\da-fA-F]{2}:[\da-fA-F]{2}:[\da-fA-F]{2}:[\da-fA-F]{2}:[\da-fA-F]{2})`)
	}

	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := scanner.Text()
		matches := macRe.FindStringSubmatch(line)
		if len(matches) >= 3 {
			mac := normalizeMACToColon(matches[2])
			// Skip broadcast/multicast
			if mac == "FF:FF:FF:FF:FF:FF" || mac == "ff:ff:ff:ff:ff:ff" {
				continue
			}
			devices = append(devices, Device{
				IP:  matches[1],
				MAC: strings.ToUpper(mac),
			})
		}
	}

	return devices, nil
}

func normalizeMACToColon(mac string) string {
	return strings.ReplaceAll(mac, "-", ":")
}

func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}
