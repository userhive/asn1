// Package ldap provides a ldap implementation.
package ldap

import (
	"context"
	"log"
)

// contextKey is the context key type
type contextKey int

// contextKey values.
const (
	loggerKey contextKey = iota
	sessionKey
)

// SessionID returns the context's session id.
func SessionID(ctx context.Context) string {
	s, ok := ctx.Value(sessionKey).(*Session)
	if !ok {
		return ""
	}
	return s.id
}

// SessionValue returns the named value from the context's session.
func SessionValue(ctx context.Context, name string) interface{} {
	s, ok := ctx.Value(sessionKey).(*Session)
	if !ok {
		return nil
	}
	return s.get(name)
}

// SessionSetValue sets a named value in the context's session.
func SessionSetValue(ctx context.Context, name string, value interface{}) {
	s, ok := ctx.Value(sessionKey).(*Session)
	if ok {
		s.set(name, value)
	}
}

// WithLogf creates a new context with the specified log func.
func WithLogf(ctx context.Context, logf func(string, ...interface{})) context.Context {
	return context.WithValue(ctx, loggerKey, logf)
}

// Logf returns the context's log func.
func Logf(ctx context.Context, s string, v ...interface{}) {
	logf, ok := ctx.Value(loggerKey).(func(string, ...interface{}))
	if !ok {
		logf = log.Printf
	}
	logf(s, v...)
}
