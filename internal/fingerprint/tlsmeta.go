package fingerprint

// ValidTLSRecord checks a TLS handshake record prefix.
// A leading 0x16 0x03 is not enough: the record length, handshake type, and
// handshake length have to agree. The captured banner may be shorter than the
// declared record, which is how the sample ClientHello prefix is shaped.
func ValidTLSRecord(banner string) bool {
	if len(banner) < 9 {
		return false
	}
	if banner[0] != 0x16 || banner[1] != 0x03 || banner[2] > 0x04 {
		return false
	}
	recordLen := int(banner[3])<<8 | int(banner[4])
	if recordLen < 4 || recordLen > 16384 {
		return false
	}
	handshakeType := banner[5]
	if handshakeType != 0x01 && handshakeType != 0x02 {
		return false
	}
	handshakeLen := int(banner[6])<<16 | int(banner[7])<<8 | int(banner[8])
	return 4+handshakeLen == recordLen
}
