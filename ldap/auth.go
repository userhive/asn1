package ldap

import (
	"context"

	"github.com/userhive/asn1/ldap/ldaputil"
)

// AuthHandler is the interface for an auth handler.
type AuthHandler interface {
	Bind(context.Context, *BindRequest) (*BindResponse, error)
	Auth(context.Context, ldaputil.Application) (ldaputil.Result, error)
	Extended(context.Context, ExtendedOp) (ldaputil.Result, error)
}

// SessionBindFunc is the session bind func type.
type SessionBindFunc func(context.Context, string, string) (ldaputil.Result, error)

// SessionAuthFunc is the session auth func type.
type SessionAuthFunc func(context.Context, ldaputil.Application, string) (ldaputil.Result, error)

// SessionExtendedFunc is the sesssion extended auth func type.
type SessionExtendedFunc func(context.Context, ExtendedOp, string) (ldaputil.Result, error)

// SessionAuthHandler is a session auth handler.
type SessionAuthHandler struct {
	bind     SessionBindFunc
	auth     SessionAuthFunc
	extended SessionExtendedFunc
}

// NewSessionAuthHandler creates a new session auth handler.
func NewSessionAuthHandler(bind SessionBindFunc, auth SessionAuthFunc, extended SessionExtendedFunc) AuthHandler {
	return SessionAuthHandler{
		bind:     bind,
		auth:     auth,
		extended: extended,
	}
}

// Bind satisfies the AuthHandler interface.
func (h SessionAuthHandler) Bind(ctx context.Context, req *BindRequest) (*BindResponse, error) {
	sess, ok := ctx.Value(sessionKey).(*Session)
	if !ok {
		return nil, NewError(ldaputil.ResultOperationsError, "invalid session")
	}
	result, err := h.bind(ctx, req.Username, req.Password)
	if err != nil {
		return nil, err
	}
	if result == ldaputil.ResultSuccess {
		sess.set("dn", req.Username)
	}
	return &BindResponse{
		Result:    result,
		MatchedDN: req.Username,
	}, nil
}

// Auth satisfies the AuthHandler interface.
func (h SessionAuthHandler) Auth(ctx context.Context, app ldaputil.Application) (ldaputil.Result, error) {
	sess, ok := ctx.Value(sessionKey).(*Session)
	if !ok {
		return ldaputil.ResultOperationsError, NewError(ldaputil.ResultOperationsError, "invalid session")
	}
	return h.auth(ctx, app, sess.get("dn").(string))
}

// Extended satisfies the AuthHandler interface.
func (h SessionAuthHandler) Extended(ctx context.Context, op ExtendedOp) (ldaputil.Result, error) {
	sess, ok := ctx.Value(sessionKey).(*Session)
	if !ok {
		return ldaputil.ResultOperationsError, NewError(ldaputil.ResultOperationsError, "invalid session")
	}
	return h.extended(ctx, op, sess.get("dn").(string))
}
