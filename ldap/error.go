package ldap

import (
	"fmt"

	"github.com/userhive/asn1/ber"
	"github.com/userhive/asn1/ldap/ldaputil"
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
	ErrRespChanClosed                   ServerError = "response channel closed"
	ErrCouldNotRetrieveMessage          ServerError = "could not retrieve message"
)

// Error is a ldap error.
type Error struct {
	Result  ldaputil.Result
	Matched string
	Message string
}

// NewError creates a new ldap error.
func NewError(result ldaputil.Result, message string) *Error {
	return &Error{
		Result:  result,
		Message: message,
	}
}

// NewErrorf creates a new ldap error using fmt.Sprintf.
func NewErrorf(result ldaputil.Result, message string, v ...interface{}) *Error {
	return &Error{
		Result:  result,
		Message: fmt.Sprintf(message, v...),
	}
}

// Error satisfies the error interface.
func (err *Error) Error() string {
	return fmt.Sprintf("%s (%d)", err.Message, err.Result)
}

// GetError creates an Error out of a BER packet representing a Result The
// return is an error object. It can be casted to a Error structure.  This
// function returns nil if resultCode in the Result sequence is success(0).
func GetError(p *ber.Packet) error {
	if p == nil {
		return &Error{Result: ldaputil.ResultClientError, Message: "empty packet"}
	}
	if len(p.Children) >= 2 {
		res := p.Children[1]
		if res == nil {
			return &Error{Result: ldaputil.ResultClientError, Message: "empty response in packet"}
		}
		if res.Class == ber.ClassApplication && res.Type == ber.TypeConstructed && len(res.Children) >= 3 {
			result := ldaputil.Result(res.Children[0].Value.(int64))
			if result == ldaputil.ResultSuccess {
				return nil
			}
			return &Error{
				Result:  result,
				Matched: res.Children[1].Value.(string),
				Message: res.Children[2].Value.(string),
			}
		}
	}
	return &Error{Result: ldaputil.ResultClientError, Message: "invalid packet format"}
}

// IsErrorOf returns true if the given error is an LDAP error with any one of the given result codes
func IsErrorOf(err error, results ...ldaputil.Result) bool {
	if err == nil {
		return false
	}
	e, ok := err.(*Error)
	if !ok {
		return false
	}
	for _, result := range results {
		if e.Result == result {
			return true
		}
	}
	return false
}
