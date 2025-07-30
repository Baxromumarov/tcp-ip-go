package ip

import "fmt"

type IpError string

const (
	ErrInvalidIP      IpError = "invalid IP address"
	ErrInvalidVersion IpError = "invalid IP version"
	ErrPacketTooShort IpError = "packet too short"
	ErrInvalidHeader  IpError = "invalid header"
	ErrChecksumFailed IpError = "checksum validation failed"
)

func (e IpError) Error() string {
	return string(e)
}

func (e IpError) WithContext(context string) error {
	return fmt.Errorf("%s: %s", e, context)
}
