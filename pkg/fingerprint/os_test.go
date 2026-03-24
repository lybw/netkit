package fingerprint

import "testing"

func TestClassifyByTTL(t *testing.T) {
	tests := []struct {
		ttl    int
		wantOS string
	}{
		{64, "Linux/macOS/Unix"},
		{128, "Windows"},
		{255, "Network Device (Cisco/Router/Switch)"},
		{254, "Solaris/AIX"},
		{32, "Unknown (very low TTL, possibly custom)"},
	}

	for _, tt := range tests {
		g := classifyByTTL(tt.ttl)
		if g.OS != tt.wantOS {
			t.Errorf("classifyByTTL(%d) = %q, want %q", tt.ttl, g.OS, tt.wantOS)
		}
		if g.TTL != tt.ttl {
			t.Errorf("TTL field = %d, want %d", g.TTL, tt.ttl)
		}
	}
}

func TestDeviceType(t *testing.T) {
	tests := []struct {
		ports []int
		want  string
	}{
		{[]int{22, 80, 443}, "Server"},
		{[]int{135, 445, 3389}, "Windows Server"},
		{[]int{135, 445}, "Windows Workstation"},
		{[]int{9100, 80}, "Printer"},
		{[]int{554, 80}, "Camera/DVR"},
		{[]int{22}, "Linux Server"},
		{[]int{161, 22}, "Network Device"},
		{[]int{3306, 22}, "Database Server"},
		{[]int{80, 443}, "Web Server"},
	}

	for _, tt := range tests {
		got := DeviceType(tt.ports)
		if got != tt.want {
			t.Errorf("DeviceType(%v) = %q, want %q", tt.ports, got, tt.want)
		}
	}
}
