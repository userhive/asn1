package ldap

import (
	"fmt"
)

// ServerError is a server error.
type ServerError string

// Error satisfies the error interface.
func (err ServerError) Error() string {
	return "ldap: " + string(err)
}

// Error values.
const (
	ErrServerShutdown                   ServerError = "server shutdown"
	ErrNilHandler                       ServerError = "nil handler"
	ErrPacketHasInvalidNumberOfChildren ServerError = "packet has invalid number of children"
	ErrPacketHasInvalidMessageID        ServerError = "packet has invalid message id"
	ErrPacketHasInvalidClass            ServerError = "packet has invalid class"
)

// Error is a ldap error.
type Error struct {
	Result  Result
	Message string
	Matched string
}

// NewError creates a new ldap error.
func NewError(result Result, message string) *Error {
	return &Error{
		Result:  result,
		Message: message,
	}
}

// NewErrorf creates a new ldap error using fmt.Sprintf.
func NewErrorf(result Result, message string, v ...interface{}) *Error {
	return &Error{
		Result:  result,
		Message: fmt.Sprintf(message, v...),
	}
}

// Error satisfies the error interface.
func (err *Error) Error() string {
	return fmt.Sprintf("%s (%d)", err.Message, err.Result)
}
