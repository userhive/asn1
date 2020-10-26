package ldap

//go:generate stringer -type Scope -trimprefix Scope
//go:generate stringer -type DerefAliases -trimprefix DerefAliases

import (
	"context"
	"time"

	"github.com/userhive/asn1/ber"
	"github.com/userhive/asn1/ldap/ldaputil"
)

type SearchHandler interface {
	Search(context.Context, *SearchRequest) (*SearchResponse, error)
}

type SearchHandlerFunc func(context.Context, *SearchRequest) (*SearchResponse, error)

func (f SearchHandlerFunc) Search(ctx context.Context, req *SearchRequest) (*SearchResponse, error) {
	return f(ctx, req)
}

type SearchRequest struct {
	BaseObject   string
	Scope        Scope
	DerefAliases DerefAliases
	SizeLimit    int64
	TimeLimit    time.Duration
	TypesOnly    bool
	Filter       *ber.Packet
	Attributes   []string
}

func ParseSearchRequest(req *Request) (*SearchRequest, error) {
	if len(req.Packet.Children) != 8 {
		return nil, NewErrorf(ldaputil.ResultProtocolError, "invalid search request, children missing (8 != %d)", len(req.Packet.Children))
	}
	baseObject := readString(req.Packet.Children[0])
	scope := Scope(readInt64(req.Packet.Children[1]))
	derefAliases := DerefAliases(readInt64(req.Packet.Children[2]))
	sizeLimit := readInt64(req.Packet.Children[3])
	timeLimit := time.Duration(readInt64(req.Packet.Children[4])) * time.Second
	typesOnly := readBool(req.Packet.Children[5])
	attributes := readStringSlice(req.Packet.Children[7])
	return &SearchRequest{
		BaseObject:   baseObject,
		Scope:        scope,
		DerefAliases: derefAliases,
		SizeLimit:    sizeLimit,
		TimeLimit:    timeLimit,
		TypesOnly:    typesOnly,
		Filter:       req.Packet.Children[6],
		Attributes:   attributes,
	}, nil
}

type SearchEntryResult interface {
	Columns() ([]string, error)
	Next() bool
	Scan(...interface{}) error
	Err() error
	Close() error
}

type SearchEntry struct {
}

func (v *SearchEntry) Encode(w ResponseWriter) error {
	return nil
}

type SearchRefResult interface {
	Next() bool
	Scan(...interface{}) error
	Err() error
	Close() error
}

type SearchRef struct {
}

func (v *SearchRef) Encode(w ResponseWriter) error {
	return nil
}

type SearchResponse struct {
	Result    ldaputil.Result
	MatchedDN string
	Entries   SearchEntryResult
	Refs      SearchRefResult
}

// Encode satisfies the Encoder interface.
func (res *SearchResponse) Encode(ctx context.Context, w ResponseWriter) error {
	if res.Entries != nil {
		defer res.Entries.Close()
	}
	if res.Refs != nil {
		defer res.Refs.Close()
	}
	var err error
	if res.Entries != nil {
		for res.Entries.Next() {
			entry := new(SearchEntry)
			if err = res.Entries.Scan(entry); err != nil {
				return w.WriteError(ldaputil.ApplicationSearchResultDone, NewError(ldaputil.ResultOtherError, "server error encountered while scanning search result"))
			}
			if err = entry.Encode(w); err != nil {
				return w.WriteError(ldaputil.ApplicationSearchResultDone, NewError(ldaputil.ResultOtherError, "error encountered while encoding search result"))
			}
		}
		if err = res.Entries.Err(); err != nil {
			Logf(ctx, "encountered error while processing search results: %v", err)
			return w.WriteError(ldaputil.ApplicationSearchResultDone, NewError(ldaputil.ResultOtherError, "server error encountered processing search results"))
		}
	}
	if res.Refs != nil {
		for res.Refs.Next() {
			referral := new(SearchRef)
			if err = res.Entries.Scan(referral); err != nil {
				return w.WriteError(ldaputil.ApplicationSearchResultDone, NewError(ldaputil.ResultOtherError, "server error encountered while scanning search referral"))
			}
			if err = referral.Encode(w); err != nil {
				return w.WriteError(ldaputil.ApplicationSearchResultDone, NewError(ldaputil.ResultOtherError, "error encountered while encoding search referral"))
			}
		}
		if err = res.Refs.Err(); err != nil {
			Logf(ctx, "encountered error while processing search referrals: %v", err)
			return w.WriteError(ldaputil.ApplicationSearchResultDone, NewError(ldaputil.ResultOtherError, "server error encountered processing search referrals"))
		}
	}
	return res.WriteDone(w)
}

func (res *SearchResponse) WriteDone(w ResponseWriter) error {
	return w.WriteResult(ldaputil.ApplicationSearchResultDone, res.Result, res.MatchedDN, res.Result.String())
}

type QueryHandler interface {
	Query()
}

func NewSearchQueryHandler(h QueryHandler) SearchHandler {
	return nil
}

// Scope is the scope enum.
type Scope int

// Scope values.
const (
	ScopeBaseObject Scope = iota
	ScopeSingleLevel
	ScopeWholeSubtree
)

// DerefAliases is the deref aliases enum.
type DerefAliases int

// DerefAliases values.
const (
	DerefAliasesNever DerefAliases = iota
	DerefAliasesInSearching
	DerefAliasesFindingBaseObject
	DerefAliasesAlways
)
