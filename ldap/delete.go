package ldap

import (
	"context"
	"errors"

	"github.com/userhive/asn1/ldap/ldaputil"
)

type DeleteHandler interface {
	Delete(context.Context, *DeleteRequest) (*DeleteResponse, error)
}

type DeleteHandlerFunc func(context.Context, *DeleteRequest) (*DeleteResponse, error)

func (f DeleteHandlerFunc) Delete(ctx context.Context, req *DeleteRequest) (*DeleteResponse, error) {
	return f(ctx, req)
}

type DeleteRequest struct{}

func ParseDeleteRequest(req *Request) (*DeleteRequest, error) {
	return &DeleteRequest{}, nil
}

type DeleteResponse struct{}

// Encode satisfies the Encoder interface.
func (res *DeleteResponse) Encode(_ context.Context, w ResponseWriter) error {
	return w.WriteError(ldaputil.ApplicationDeleteResponse, errors.New("not implemented"))
}
