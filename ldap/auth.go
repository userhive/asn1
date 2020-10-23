package ldap

import (
	"context"
)

// AuthHandler is the interface for an auth handler.
type AuthHandler interface {
	Bind(context.Context, *BindRequest) (*BindResponse, error)
	Auth(context.Context, Application) (Result, error)
	Extended(context.Context, ExtendedOp) (Result, error)
}

// SessionBindFunc is the session bind func type.
type SessionBindFunc func(context.Context, string, string) (Result, error)

// SessionAuthFunc is the session auth func type.
type SessionAuthFunc func(context.Context, Application, string) (Result, error)

// SessionExtendedFunc is the sesssion extended auth func type.
type SessionExtendedFunc func(context.Context, ExtendedOp, string) (Result, error)

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
		return nil, NewError(ResultOperationsError, "invalid session")
	}
	result, err := h.bind(ctx, req.Username, req.Password)
	if err != nil {
		return nil, err
	}
	if result == ResultSuccess {
		sess.set("dn", req.Username)
	}
	return &BindResponse{
		Result:    result,
		MatchedDN: req.Username,
	}, nil
}

// Auth satisfies the AuthHandler interface.
func (h SessionAuthHandler) Auth(ctx context.Context, app Application) (Result, error) {
	sess, ok := ctx.Value(sessionKey).(*Session)
	if !ok {
		return ResultOperationsError, NewError(ResultOperationsError, "invalid session")
	}
	return h.auth(ctx, app, sess.get("dn").(string))
}

// Extended satisfies the AuthHandler interface.
func (h SessionAuthHandler) Extended(ctx context.Context, op ExtendedOp) (Result, error) {
	sess, ok := ctx.Value(sessionKey).(*Session)
	if !ok {
		return ResultOperationsError, NewError(ResultOperationsError, "invalid session")
	}
	return h.extended(ctx, op, sess.get("dn").(string))
}
