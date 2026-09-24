package main

// Linux-only data sources of the mon module (no exec: the CGI talks to the kernel directly).

import "syscall"

// monNeighDump dumps the kernel neighbour table (ARP + NDP) over rtnetlink.
func monNeighDump() ([]monNeigh, error) {
	b, err := syscall.NetlinkRIB(syscall.RTM_GETNEIGH, syscall.AF_UNSPEC)
	if err != nil {
		return nil, err
	}
	msgs, err := syscall.ParseNetlinkMessage(b)
	if err != nil {
		return nil, err
	}
	var out []monNeigh
	for _, m := range msgs {
		if m.Header.Type != syscall.RTM_NEWNEIGH {
			continue
		}
		if n, ok := monParseNeigh(m.Data); ok {
			out = append(out, n)
		}
	}
	return out, nil
}

// monReadKlog returns the kernel ring buffer (syslog(2) READ_ALL, like dmesg).
func monReadKlog() (string, error) {
	const readAll, sizeBuffer = 3, 10
	n, err := syscall.Klogctl(sizeBuffer, nil)
	if err != nil {
		return "", err
	}
	if n <= 0 || n > 16<<20 {
		n = 1 << 20
	}
	buf := make([]byte, n)
	m, err := syscall.Klogctl(readAll, buf)
	if err != nil {
		return "", err
	}
	return string(buf[:m]), nil
}
