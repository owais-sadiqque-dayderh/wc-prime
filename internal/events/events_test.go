package events

import (
	"fmt"
	"testing"
)

func TestRecentAndWrap(t *testing.T) {
	l := New(3)
	if got := l.Recent(); len(got) != 0 {
		t.Fatalf("initial events=%v", got)
	}
	l.Info("event %d", 1)
	l.Warn("event %d", 2)
	got := l.Recent()
	if len(got) != 2 || got[0].Message != "event 2" || got[0].Level != "warn" || got[1].Message != "event 1" || got[1].Time.IsZero() {
		t.Fatalf("recent=%+v", got)
	}
	got[0].Message = "changed copy"
	if l.Recent()[0].Message != "event 2" {
		t.Fatal("Recent exposes ring storage")
	}
	for i := 3; i <= 8; i++ {
		l.Error("event %d", i)
	}
	got = l.Recent()
	if len(got) != 3 {
		t.Fatalf("len=%d", len(got))
	}
	for i, e := range got {
		if e.Message != fmt.Sprintf("event %d", 8-i) || e.Level != "error" {
			t.Errorf("event[%d]=%+v", i, e)
		}
	}
}
