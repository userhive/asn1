package ldap

import (
	"context"
)

type AbandonHandler interface {
	Abandon(context.Context, *AbandonRequest) (*AbandonResponse, error)
}

type AbandonHandlerFunc func(context.Context, *AbandonRequest) (*AbandonResponse, error)

func (f AbandonHandlerFunc) Abandon(ctx context.Context, req *AbandonRequest) (*AbandonResponse, error) {
	return f(ctx, req)
}

type AbandonRequest struct {
	ID int64
}

func NewAbandonRequest(req *Request) (*AbandonRequest, error) {
	// abandon requests never send an error message, so ignore ...
	var id int64
	if len(req.Packet.Children) == 1 {
		id, _ = req.Packet.Children[0].Value.(int64)
	}
	return &AbandonRequest{
		ID: id,
	}, nil
}

type AbandonResponse struct{}

// Encode satisfies the Encoder interface.
func (res *AbandonResponse) Encode(_ context.Context, w ResponseWriter) error {
	// abandon requests never send an error message, so ignore ...
	return nil
}
