package model

// Input is one raw scan record accepted by POST /fingerprint.
type Input struct {
	IP     string `json:"ip"`
	Port   int    `json:"port"`
	Banner string `json:"banner"`
}

// Result is one identification. Field order is the response contract.
// Empty strings and a zero confidence stay present; they are not omitted.
type Result struct {
	IP         string  `json:"ip"`
	Port       int     `json:"port"`
	Protocol   string  `json:"protocol"`
	Product    string  `json:"product"`
	Version    string  `json:"version"`
	OSHint     string  `json:"os_hint"`
	Confidence float64 `json:"confidence"`
}

// Unknown is the stable result for a banner the engine cannot classify.
func Unknown(ip string, port int) Result {
	return Result{
		IP:         ip,
		Port:       port,
		Protocol:   "unknown",
		Product:    "",
		Version:    "",
		OSHint:     "",
		Confidence: 0,
	}
}
