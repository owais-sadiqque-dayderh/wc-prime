// Package events keeps a small in-memory ring of recent service events for
// the UI, and mirrors them to the standard logger.
package events

import (
	"fmt"
	"log"
	"sync"
	"time"
)

type Event struct {
	Time    time.Time `json:"time"`
	Level   string    `json:"level"` // info | warn | error
	Message string    `json:"message"`
}

type Log struct {
	mu   sync.Mutex
	buf  []Event
	next int
	full bool
}

func New(size int) *Log { return &Log{buf: make([]Event, size)} }

func (l *Log) add(level, format string, args ...any) {
	e := Event{Time: time.Now(), Level: level, Message: fmt.Sprintf(format, args...)}
	log.Printf("%-5s %s", level, e.Message)
	l.mu.Lock()
	l.buf[l.next] = e
	l.next = (l.next + 1) % len(l.buf)
	l.full = l.full || l.next == 0
	l.mu.Unlock()
}

func (l *Log) Info(format string, args ...any)  { l.add("info", format, args...) }
func (l *Log) Warn(format string, args ...any)  { l.add("warn", format, args...) }
func (l *Log) Error(format string, args ...any) { l.add("error", format, args...) }

// Recent returns events newest first.
func (l *Log) Recent() []Event {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := l.next
	if l.full {
		n = len(l.buf)
	}
	out := make([]Event, 0, n)
	for i := 1; i <= n; i++ {
		out = append(out, l.buf[(l.next-i+len(l.buf))%len(l.buf)])
	}
	return out
}
