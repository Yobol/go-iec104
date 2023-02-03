package iec104

type DirectionMode string

const (
	DirectionModeMonitor  = "monitor"  // from server to client
	DirectionModeControl  = "control"  // from client to server
	DirectionModeReversed = "reversed" // server is sending commands and client is sending data
)
