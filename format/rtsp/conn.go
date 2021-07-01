package rtsp

import (
	"encoding/base64"
	"net"
	"time"
)

type connWithTimeout struct {
	Timeout time.Duration
	net.Conn
}

func (self connWithTimeout) Read(p []byte) (n int, err error) {
	if self.Timeout > 0 {
		self.Conn.SetReadDeadline(time.Now().Add(self.Timeout))
	}
	return self.Conn.Read(p)
}

func (self connWithTimeout) Write(p []byte) (n int, err error) {
	if self.Timeout > 0 {
		self.Conn.SetWriteDeadline(time.Now().Add(self.Timeout))
	}
	return self.Conn.Write(p)
}

type connWithTimeoutBase64 struct {
	Timeout time.Duration
	net.Conn
}

func (self connWithTimeoutBase64) Read(p []byte) (n int, err error) {
	if self.Timeout > 0 {
		self.Conn.SetReadDeadline(time.Now().Add(self.Timeout))
	}
	return self.Conn.Read(p)
}

func (self connWithTimeoutBase64) Write(p []byte) (n int, err error) {
	if self.Timeout > 0 {
		self.Conn.SetWriteDeadline(time.Now().Add(self.Timeout))
	}
	b64 := base64.StdEncoding.EncodeToString(p)
	return self.Conn.Write([]byte(b64))
}

func (self connWithTimeoutBase64) WriteRaw(p []byte) (n int, err error) {
	if self.Timeout > 0 {
		self.Conn.SetWriteDeadline(time.Now().Add(self.Timeout))
	}
	return self.Conn.Write(p)
}
