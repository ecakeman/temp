package fingerprint

import "testing"

func TestParseHTTP(t *testing.T) {
	msg := ParseHTTP("HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\n\r\nApache/2.4.57")
	if !msg.OK || msg.Server != "nginx/1.24.0" || msg.Conflict {
		t.Fatalf("%+v", msg)
	}
	conflict := ParseHTTP("HTTP/1.1 200 OK\nServer: nginx/1.24.0\nServer: Apache/2.4.57\n")
	if !conflict.OK || !conflict.Conflict || conflict.Server != "" {
		t.Fatalf("%+v", conflict)
	}
	same := ParseHTTP("HTTP/1.1 200 OK\r\nServer: Jetty/9.4.51\r\nserver: Jetty/9.4.51\r\n")
	if !same.OK || same.Conflict || same.Server != "Jetty/9.4.51" {
		t.Fatalf("%+v", same)
	}
	bad := ParseHTTP("HTTP/1.1 999 Weird\r\nServer: nginx/1.24.0\r\n")
	if bad.OK {
		t.Fatalf("%+v", bad)
	}
	bare := ParseHTTP("not a response HTTP/1.1 200 OK\r\nServer: nginx/1.24.0")
	if bare.OK {
		t.Fatalf("%+v", bare)
	}
}

func TestValidTLSRecord(t *testing.T) {
	sample := string([]byte{0x16, 0x03, 0x01, 0x00, 0xa5, 0x01, 0x00, 0x00, 0xa1})
	if !ValidTLSRecord(sample) {
		t.Fatal("sample prefix should validate")
	}
	short := string([]byte{0x16, 0x03, 0x01})
	if ValidTLSRecord(short) {
		t.Fatal("short prefix validated")
	}
}
