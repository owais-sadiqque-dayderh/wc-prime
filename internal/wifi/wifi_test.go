package wifi

import (
	"reflect"
	"testing"
)

func TestDedupe(t *testing.T) {
	want := []AP{{"A", 90, "WPA3"}, {"B", 90, "WPA2"}, {"C", 20, "Open"}}
	got := dedupe([]AP{{"", 100, ""}, {"B", 90, "WPA2"}, {"A", 30, "WPA2"}, {"C", 20, "Open"}, {"A", 90, "WPA3"}})
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}

func TestDBmToPercent(t *testing.T) {
	for _, tt := range []struct{ dbm, want int }{{-120, 0}, {-100, 0}, {-75, 50}, {-55, 90}, {-50, 100}, {-20, 100}} {
		if got := dBmToPercent(tt.dbm); got != tt.want {
			t.Errorf("dBmToPercent(%d)=%d, want %d", tt.dbm, got, tt.want)
		}
	}
}
