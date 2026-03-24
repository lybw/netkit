// Package oui provides MAC address to vendor/manufacturer lookup
// using the IEEE OUI (Organizationally Unique Identifier) database.
package oui

import (
	"strings"
	"sync"
)

// DB is the OUI lookup database.
type DB struct {
	mu      sync.RWMutex
	entries map[string]string // uppercase prefix "00:1A:2B" -> vendor
}

// DefaultDB is a built-in database with common vendor prefixes.
var DefaultDB = newDefaultDB()

func newDefaultDB() *DB {
	db := &DB{entries: make(map[string]string, 512)}

	// Common vendors - a practical subset for LAN discovery
	vendors := map[string]string{
		// Apple
		"00:03:93": "Apple", "00:05:02": "Apple", "00:0A:27": "Apple",
		"00:0A:95": "Apple", "00:0D:93": "Apple", "00:10:FA": "Apple",
		"00:11:24": "Apple", "00:14:51": "Apple", "00:16:CB": "Apple",
		"00:17:F2": "Apple", "00:19:E3": "Apple", "00:1B:63": "Apple",
		"00:1C:B3": "Apple", "00:1D:4F": "Apple", "00:1E:52": "Apple",
		"00:1E:C2": "Apple", "00:1F:5B": "Apple", "00:1F:F3": "Apple",
		"00:21:E9": "Apple", "00:22:41": "Apple", "00:23:12": "Apple",
		"00:23:32": "Apple", "00:23:6C": "Apple", "00:23:DF": "Apple",
		"00:24:36": "Apple", "00:25:00": "Apple", "00:25:4B": "Apple",
		"00:25:BC": "Apple", "00:26:08": "Apple", "00:26:4A": "Apple",
		"00:26:B0": "Apple", "00:26:BB": "Apple",
		"3C:15:C2": "Apple", "28:CF:DA": "Apple",
		"AC:DE:48": "Apple", "A8:5C:2C": "Apple",

		// Samsung
		"00:07:AB": "Samsung", "00:12:47": "Samsung", "00:12:FB": "Samsung",
		"00:13:77": "Samsung", "00:15:99": "Samsung", "00:16:32": "Samsung",
		"00:16:6B": "Samsung", "00:16:DB": "Samsung", "00:17:C9": "Samsung",
		"00:17:D5": "Samsung", "00:18:AF": "Samsung", "00:1A:8A": "Samsung",
		"00:1B:98": "Samsung", "00:1C:43": "Samsung", "00:1D:25": "Samsung",
		"00:1D:F6": "Samsung", "00:1E:75": "Samsung", "00:1F:CC": "Samsung",
		"00:21:19": "Samsung", "00:21:D1": "Samsung", "00:21:D2": "Samsung",
		"00:24:54": "Samsung", "00:24:90": "Samsung", "00:24:91": "Samsung",
		"00:25:66": "Samsung", "00:26:37": "Samsung",
		"8C:77:12": "Samsung", "50:01:BB": "Samsung",

		// Huawei
		"00:E0:FC": "Huawei", "00:1E:10": "Huawei", "00:18:82": "Huawei",
		"00:25:9E": "Huawei", "00:46:4B": "Huawei", "00:9A:CD": "Huawei",
		"04:02:1F": "Huawei", "04:25:C5": "Huawei", "04:33:89": "Huawei",
		"04:4F:4C": "Huawei", "04:B0:E7": "Huawei", "04:C0:6F": "Huawei",
		"04:F9:38": "Huawei", "08:19:A6": "Huawei", "08:63:61": "Huawei",
		"20:A6:80": "Huawei", "24:09:95": "Huawei",

		// Xiaomi
		"00:9E:C8": "Xiaomi", "04:CF:8C": "Xiaomi", "08:86:3B": "Xiaomi",
		"0C:1D:AF": "Xiaomi", "10:2A:B3": "Xiaomi", "14:F6:5A": "Xiaomi",
		"18:59:36": "Xiaomi", "1C:5A:3E": "Xiaomi", "20:82:C0": "Xiaomi",
		"28:6C:07": "Xiaomi", "28:E3:1F": "Xiaomi", "2C:D0:5A": "Xiaomi",
		"34:80:B3": "Xiaomi", "34:CE:00": "Xiaomi", "38:A4:ED": "Xiaomi",
		"3C:BD:3E": "Xiaomi", "44:23:7C": "Xiaomi", "50:64:2B": "Xiaomi",
		"58:44:98": "Xiaomi", "64:09:80": "Xiaomi", "64:B4:73": "Xiaomi",
		"7C:1D:D9": "Xiaomi", "84:F3:EB": "Xiaomi",

		// Cisco
		"00:00:0C": "Cisco", "00:01:42": "Cisco", "00:01:43": "Cisco",
		"00:01:63": "Cisco", "00:01:64": "Cisco", "00:01:96": "Cisco",
		"00:01:97": "Cisco", "00:01:C7": "Cisco", "00:01:C9": "Cisco",
		"00:02:16": "Cisco", "00:02:17": "Cisco", "00:02:3D": "Cisco",
		"00:02:4A": "Cisco", "00:02:4B": "Cisco", "00:02:7D": "Cisco",
		"00:02:7E": "Cisco", "00:02:B9": "Cisco", "00:02:BA": "Cisco",
		"00:02:FC": "Cisco", "00:02:FD": "Cisco",

		// H3C / HP Networking
		"00:0F:E2": "H3C", "00:23:89": "H3C", "00:26:CA": "H3C",
		"1C:6A:7A": "H3C", "3C:8C:40": "H3C", "58:6A:B1": "H3C",
		"70:F9:6D": "H3C", "80:F6:2E": "H3C",

		// TP-Link
		"00:27:19": "TP-Link", "14:CF:92": "TP-Link", "30:B5:C2": "TP-Link",
		"50:3E:AA": "TP-Link", "54:C8:0F": "TP-Link", "60:E3:27": "TP-Link",
		"74:DA:88": "TP-Link", "94:0C:6D": "TP-Link", "B0:4E:26": "TP-Link",
		"C0:25:E9": "TP-Link", "CC:32:E5": "TP-Link", "D8:07:B6": "TP-Link",
		"EC:08:6B": "TP-Link", "F4:F2:6D": "TP-Link",

		// D-Link
		"00:05:5D": "D-Link", "00:0D:88": "D-Link", "00:0F:3D": "D-Link",
		"00:11:95": "D-Link", "00:13:46": "D-Link", "00:15:E9": "D-Link",
		"00:17:9A": "D-Link", "00:19:5B": "D-Link", "00:1B:11": "D-Link",
		"00:1C:F0": "D-Link", "00:1E:58": "D-Link", "00:21:91": "D-Link",
		"00:22:B0": "D-Link", "00:24:01": "D-Link", "00:26:5A": "D-Link",

		// Dell
		"00:06:5B": "Dell", "00:08:74": "Dell", "00:0B:DB": "Dell",
		"00:0D:56": "Dell", "00:0F:1F": "Dell", "00:11:43": "Dell",
		"00:12:3F": "Dell", "00:13:72": "Dell", "00:14:22": "Dell",
		"00:15:C5": "Dell", "00:18:8B": "Dell", "00:19:B9": "Dell",
		"00:1A:A0": "Dell", "00:1C:23": "Dell", "00:1D:09": "Dell",
		"00:1E:4F": "Dell", "00:1E:C9": "Dell", "00:21:70": "Dell",
		"00:22:19": "Dell", "00:23:AE": "Dell", "00:24:E8": "Dell",
		"00:25:64": "Dell", "00:26:B9": "Dell",

		// Intel
		"00:02:B3": "Intel", "00:03:47": "Intel", "00:04:23": "Intel",
		"00:07:E9": "Intel", "00:0C:F1": "Intel", "00:0E:0C": "Intel",
		"00:0E:35": "Intel", "00:11:11": "Intel", "00:12:F0": "Intel",
		"00:13:02": "Intel", "00:13:20": "Intel", "00:13:CE": "Intel",
		"00:13:E8": "Intel", "00:15:00": "Intel", "00:15:17": "Intel",
		"00:16:6F": "Intel", "00:16:76": "Intel", "00:16:EA": "Intel",
		"00:16:EB": "Intel", "00:17:35": "Intel",

		// Microsoft / Xbox
		"00:50:F2": "Microsoft", "00:03:FF": "Microsoft",
		"00:0D:3A": "Microsoft", "00:12:5A": "Microsoft",
		"00:15:5D": "Microsoft Hyper-V", "00:17:FA": "Microsoft",
		"00:1D:D8": "Microsoft", "00:22:48": "Microsoft",
		"28:18:78": "Microsoft", "7C:1E:52": "Microsoft",

		// VMware
		"00:0C:29": "VMware", "00:50:56": "VMware", "00:05:69": "VMware",

		// Raspberry Pi
		"B8:27:EB": "Raspberry Pi", "DC:A6:32": "Raspberry Pi",
		"E4:5F:01": "Raspberry Pi", "28:CD:C1": "Raspberry Pi",

		// Ruijie
		"00:1A:0A": "Ruijie", "58:69:6C": "Ruijie",
		"4C:F2:BF": "Ruijie", "00:74:9C": "Ruijie",

		// ZTE
		"00:1E:73": "ZTE", "00:19:C6": "ZTE", "00:15:67": "ZTE",
		"00:26:ED": "ZTE", "34:4B:50": "ZTE", "54:22:F8": "ZTE",

		// Hikvision
		"C0:56:E3": "Hikvision", "44:19:B6": "Hikvision",
		"54:C4:15": "Hikvision", "C4:2F:90": "Hikvision",
		"18:68:CB": "Hikvision", "28:57:BE": "Hikvision",

		// Dahua
		"3C:EF:8C": "Dahua", "4C:11:BF": "Dahua",
		"90:02:A9": "Dahua", "B0:A7:B9": "Dahua",
	}

	for prefix, vendor := range vendors {
		db.entries[strings.ToUpper(prefix)] = vendor
	}
	return db
}

// Lookup returns the vendor name for a MAC address.
// Accepts formats: "00:1A:2B:3C:4D:5E", "00-1A-2B-3C-4D-5E", "001A2B3C4D5E".
// Returns "Unknown" if not found.
func Lookup(mac string) string {
	return DefaultDB.Lookup(mac)
}

// Lookup returns the vendor name for a MAC address.
func (db *DB) Lookup(mac string) string {
	prefix := normalizePrefix(mac)
	if prefix == "" {
		return "Unknown"
	}
	db.mu.RLock()
	defer db.mu.RUnlock()
	if v, ok := db.entries[prefix]; ok {
		return v
	}
	return "Unknown"
}

// Register adds or updates a vendor entry.
func (db *DB) Register(prefix, vendor string) {
	p := normalizePrefix(prefix + ":00:00:00")
	if p == "" {
		return
	}
	db.mu.Lock()
	db.entries[p] = vendor
	db.mu.Unlock()
}

// Size returns the number of entries in the database.
func (db *DB) Size() int {
	db.mu.RLock()
	defer db.mu.RUnlock()
	return len(db.entries)
}

func normalizePrefix(mac string) string {
	// Remove separators
	clean := strings.Map(func(r rune) rune {
		if r == ':' || r == '-' || r == '.' {
			return -1
		}
		return r
	}, mac)

	if len(clean) < 6 {
		return ""
	}

	// Take first 6 hex chars, format as XX:XX:XX
	hex := strings.ToUpper(clean[:6])
	return hex[:2] + ":" + hex[2:4] + ":" + hex[4:6]
}
