package keeper

import "time"

// Health is the keeper's view of the link.
type Health string

const (
	Starting     Health = "starting"
	Disabled     Health = "wifi-off"
	Disconnected Health = "disconnected"
	Captive      Health = "captive-portal"
	NoInternet   Health = "no-internet"
	Poor         Health = "poor"
	Online       Health = "online"
	Recovering   Health = "recovering"
	Failed       Health = "error"
)

// Snapshot is what the UI shows.
type Snapshot struct {
	Health     Health    `json:"health"`
	SSID       string    `json:"ssid"`
	Signal     int       `json:"signal"` // -1 unknown
	RTTMillis  int64     `json:"rttMillis"`
	LastAction string    `json:"lastAction"`
	LastCheck  time.Time `json:"lastCheck"`
	Since      time.Time `json:"since"` // when Health last changed
	Backend    string    `json:"backend"`
}
