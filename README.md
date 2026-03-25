# netkit

[![CI](https://github.com/lybw/netkit/actions/workflows/ci.yml/badge.svg)](https://github.com/lybw/netkit/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/lybw/netkit)](https://goreportcard.com/report/github.com/lybw/netkit)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

A pragmatic Go toolkit for network operations — LAN discovery, OS fingerprinting, port scanning, and MAC vendor lookup.

Built for network engineers who prefer a single binary over a pile of Python scripts.

## Features

| Module | Description |
|--------|-------------|
| `discovery` | ARP-based LAN device discovery |
| `oui` | MAC address → vendor/manufacturer lookup |
| `portscan` | Concurrent TCP port scanner |
| `fingerprint` | OS detection via TCP/IP stack fingerprinting |

## Install

```bash
go install github.com/lybw/netkit/cmd/netkit@latest
```

## Quick Start

```bash
# Discover devices on local network
netkit discover 192.168.1.0/24

# Scan ports on a target
netkit portscan 192.168.1.1 -p 22,80,443,8080

# Lookup MAC vendor
netkit oui 00:1A:2B:3C:4D:5E

# OS fingerprint (requires root/admin)
netkit fingerprint 192.168.1.1
```

## As a Library

```go
package main

import (
    "fmt"
    "github.com/lybw/netkit/pkg/discovery"
    "github.com/lybw/netkit/pkg/oui"
)

func main() {
    // Discover devices
    devices, _ := discovery.ARP("192.168.1.0/24")
    for _, d := range devices {
        vendor := oui.Lookup(d.MAC)
        fmt.Printf("%-16s %-18s %s\n", d.IP, d.MAC, vendor)
    }
}
```

## Modules

### discovery

ARP scan to find live hosts on a subnet. Returns IP + MAC pairs.

### oui

Offline MAC-to-vendor lookup using the IEEE OUI database. Embedded via `go:embed`, no external files needed.

### portscan

Concurrent TCP connect scanner with configurable timeout and worker count.

### fingerprint

OS detection by analyzing TCP SYN-ACK responses (TTL, window size, options).

## License

MIT
