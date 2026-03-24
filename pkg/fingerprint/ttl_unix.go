//go:build !windows

package fingerprint

import (
	"net"
	"syscall"
)

func getTTL(conn net.Conn) (int, error) {
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return 0, syscall.EINVAL
	}

	rawConn, err := tcpConn.SyscallConn()
	if err != nil {
		return 0, err
	}

	var ttl int
	var ctlErr error
	err = rawConn.Control(func(fd uintptr) {
		val, err := syscall.GetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_TTL)
		if err != nil {
			ctlErr = err
			return
		}
		ttl = val
	})
	if err != nil {
		return 0, err
	}
	if ctlErr != nil {
		return 0, ctlErr
	}
	return ttl, nil
}
