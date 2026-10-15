package wifi

import (
	"reflect"
	"testing"
)

func TestParseAndroidStatus(t *testing.T) {
	for _, tt := range []struct {
		name, in string
		want     Status
	}{
		{"connected", "Wifi is enabled\nWifi is connected to \"Home Network\"\nWifiInfo: RSSI: -55(0:-56/1:-60), Link speed: 144Mbps", Status{true, true, "Home Network", 90}},
		{"missing SSID", "Wifi is enabled\nWifi is not connected\n", Status{Enabled: true, Signal: -1}},
		{"disabled", "Wifi is disabled\n", Status{Signal: -1}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := parseAndroidStatus(tt.in); got != tt.want {
				t.Fatalf("got %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestParseAndroidScan(t *testing.T) {
	const sample = `BSSID              Frequency      RSSI           Age(sec)     SSID           Flags
00:11:22:33:44:55 5180 -55(0:-56/1:-60) 0.0 Home Network [WPA2-PSK-CCMP][ESS]
00:11:22:33:44:56 2412 -80 1.2 Home Network [WPA2-PSK-CCMP][ESS]
00:11:22:33:44:57 2462 -65 0.5 Coffee Shop [ESS]
00:11:22:33:44:58 2462 -40 0.5 [WPA2-PSK-CCMP][ESS]
00:11:22:33:44:59 2462 -40 0.5
`
	want := []AP{{"Home Network", 90, "[WPA2-PSK-CCMP][ESS]"}, {"Coffee Shop", 70, "[ESS]"}}
	if got := parseAndroidScan(sample); !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}
