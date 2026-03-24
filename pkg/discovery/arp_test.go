package discovery

import "testing"

func TestParseARPOutputWindows(t *testing.T) {
	output := `
Interface: 192.168.1.100 --- 0x3
  Internet Address      Physical Address      Type
  192.168.1.1           00-0c-29-aa-bb-cc     dynamic
  192.168.1.2           d4-5d-64-11-22-33     dynamic
  192.168.1.255         ff-ff-ff-ff-ff-ff     static
`
	devices, err := parseARPOutput(output, "windows")
	if err != nil {
		t.Fatal(err)
	}
	if len(devices) != 2 {
		t.Fatalf("expected 2 devices, got %d", len(devices))
	}
	if devices[0].IP != "192.168.1.1" {
		t.Errorf("expected IP 192.168.1.1, got %s", devices[0].IP)
	}
	if devices[0].MAC != "00:0C:29:AA:BB:CC" {
		t.Errorf("expected MAC 00:0C:29:AA:BB:CC, got %s", devices[0].MAC)
	}
}

func TestParseARPOutputLinux(t *testing.T) {
	output := `
? (192.168.1.1) at 00:0c:29:aa:bb:cc [ether] on eth0
? (192.168.1.2) at d4:5d:64:11:22:33 [ether] on eth0
? (192.168.1.255) at ff:ff:ff:ff:ff:ff [ether] on eth0
`
	devices, err := parseARPOutput(output, "linux")
	if err != nil {
		t.Fatal(err)
	}
	if len(devices) != 2 {
		t.Fatalf("expected 2 devices, got %d", len(devices))
	}
	if devices[1].IP != "192.168.1.2" {
		t.Errorf("expected IP 192.168.1.2, got %s", devices[1].IP)
	}
}

func TestNormalizeMACToColon(t *testing.T) {
	got := normalizeMACToColon("00-0C-29-AA-BB-CC")
	if got != "00:0C:29:AA:BB:CC" {
		t.Errorf("expected colon format, got %s", got)
	}
}
