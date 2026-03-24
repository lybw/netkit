package oui

import "testing"

func TestLookup(t *testing.T) {
	tests := []struct {
		mac  string
		want string
	}{
		{"00:0C:29:AA:BB:CC", "VMware"},
		{"00:50:56:11:22:33", "VMware"},
		{"00:00:0C:AA:BB:CC", "Cisco"},
		{"3C:15:C2:AA:BB:CC", "Apple"},
		{"B8:27:EB:AA:BB:CC", "Raspberry Pi"},
		{"C0:56:E3:AA:BB:CC", "Hikvision"},
		{"00-0C-29-AA-BB-CC", "VMware"},       // dash format
		{"000C29AABBCC", "VMware"},             // no separator
		{"FF:FF:FF:FF:FF:FF", "Unknown"},       // broadcast
		{"", "Unknown"},                         // empty
		{"00:1A", "Unknown"},                    // too short
	}

	for _, tt := range tests {
		got := Lookup(tt.mac)
		if got != tt.want {
			t.Errorf("Lookup(%q) = %q, want %q", tt.mac, got, tt.want)
		}
	}
}

func TestDBSize(t *testing.T) {
	if DefaultDB.Size() == 0 {
		t.Error("DefaultDB should not be empty")
	}
}

func TestRegister(t *testing.T) {
	db := &DB{entries: make(map[string]string)}
	db.Register("AA:BB:CC", "TestVendor")
	got := db.Lookup("AA:BB:CC:11:22:33")
	if got != "TestVendor" {
		t.Errorf("Lookup after Register = %q, want %q", got, "TestVendor")
	}
}

func BenchmarkLookup(b *testing.B) {
	for b.Loop() {
		Lookup("00:0C:29:AA:BB:CC")
	}
}
