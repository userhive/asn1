package ldap

//go:generate stringer -type Result -trimprefix Result

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/userhive/asn1/ber"
	"github.com/userhive/asn1/ldapclient"
)

// Result is a ldap result code.
type Result int

// Result values.
const (
	ResultSuccess                            Result = 0    // Success
	ResultOperationsError                    Result = 1    // Operations Error
	ResultProtocolError                      Result = 2    // Protocol Error
	ResultTimeLimitExceeded                  Result = 3    // Time Limit Exceeded
	ResultSizeLimitExceeded                  Result = 4    // Size Limit Exceeded
	ResultCompareFalse                       Result = 5    // Compare False
	ResultCompareTrue                        Result = 6    // Compare True
	ResultAuthMethodNotSupported             Result = 7    // Auth Method Not Supported
	ResultStrongAuthRequired                 Result = 8    // Strong Auth Required
	ResultReferral                           Result = 10   // Referral
	ResultAdminLimitExceeded                 Result = 11   // Admin Limit Exceeded
	ResultUnavailableCriticalExtension       Result = 12   // Unavailable Critical Extension
	ResultConfidentialityRequired            Result = 13   // Confidentiality Required
	ResultSaslBindInProgress                 Result = 14   // Sasl Bind In Progress
	ResultNoSuchAttribute                    Result = 16   // No Such Attribute
	ResultUndefinedAttributeType             Result = 17   // Undefined Attribute Type
	ResultInappropriateMatching              Result = 18   // Inappropriate Matching
	ResultConstraintViolation                Result = 19   // Constraint Violation
	ResultAttributeOrValueExists             Result = 20   // Attribute Or Value Exists
	ResultInvalidAttributeSyntax             Result = 21   // Invalid Attribute Syntax
	ResultNoSuchObject                       Result = 32   // No Such Object
	ResultAliasProblem                       Result = 33   // Alias Problem
	ResultInvalidDNSyntax                    Result = 34   // Invalid DN Syntax
	ResultIsLeaf                             Result = 35   // Is Leaf
	ResultAliasDereferencingProblem          Result = 36   // Alias Dereferencing Problem
	ResultInappropriateAuthentication        Result = 48   // Inappropriate Authentication
	ResultInvalidCredentials                 Result = 49   // Invalid Credentials
	ResultInsufficientAccessRights           Result = 50   // Insufficient Access Rights
	ResultBusy                               Result = 51   // Busy
	ResultUnavailable                        Result = 52   // Unavailable
	ResultUnwillingToPerform                 Result = 53   // Unwilling To Perform
	ResultLoopDetect                         Result = 54   // Loop Detect
	ResultSortControlMissing                 Result = 60   // Sort Control Missing
	ResultOffsetRangeError                   Result = 61   // Result Offset Range Error
	ResultNamingViolation                    Result = 64   // Naming Violation
	ResultObjectClassViolation               Result = 65   // Object Class Violation
	ResultResultsTooLarge                    Result = 66   // Results Too Large
	ResultNotAllowedOnNonLeaf                Result = 67   // Not Allowed On Non Leaf
	ResultNotAllowedOnRDN                    Result = 68   // Not Allowed On RDN
	ResultEntryAlreadyExists                 Result = 69   // Entry Already Exists
	ResultObjectClassModsProhibited          Result = 70   // Object Class Mods Prohibited
	ResultAffectsMultipleDSAs                Result = 71   // Affects Multiple DSAs
	ResultVirtualListViewErrorOrControlError Result = 76   // Failed because of a problem related to the virtual list view
	ResultOtherError                         Result = 80   // Other
	ResultServerDown                         Result = 81   // Cannot establish a connection
	ResultLocalError                         Result = 82   // An error occurred
	ResultEncodingError                      Result = 83   // LDAP encountered an error while encoding
	ResultDecodingError                      Result = 84   // LDAP encountered an error while decoding
	ResultTimeout                            Result = 85   // LDAP timeout while waiting for a response from the server
	ResultAuthUnknown                        Result = 86   // The auth method requested in a bind request is unknown
	ResultFilterError                        Result = 87   // An error occurred while encoding the given search filter
	ResultUserCanceled                       Result = 88   // The user canceled the operation
	ResultParamError                         Result = 89   // An invalid parameter was specified
	ResultNoMemory                           Result = 90   // Out of memory error
	ResultConnectError                       Result = 91   // A connection to the server could not be established
	ResultNotSupported                       Result = 92   // An attempt has been made to use a feature not supported LDAP
	ResultControlNotFound                    Result = 93   // The controls required to perform the requested operation were not found
	ResultNoResultsReturned                  Result = 94   // No results were returned from the server
	ResultMoreResultsToReturn                Result = 95   // There are more results in the chain of results
	ResultClientLoop                         Result = 96   // A loop has been detected. For example when following referrals
	ResultReferralLimitExceeded              Result = 97   // The referral hop limit has been exceeded
	ResultCanceled                           Result = 100  // Operation was canceled
	ResultNoSuchOperation                    Result = 101  // Server has no knowledge of the operation requested for cancellation
	ResultTooLate                            Result = 112  // Too late to cancel the outstanding operation
	ResultCannotCancel                       Result = 113  // The identified operation does not support cancellation or the cancel operation cannot be performed
	ResultAssertionFailed                    Result = 114  // An assertion control given in the LDAP operation evaluated to false causing the operation to not be performed
	ResultSyncRefreshRequired                Result = 118  // Refresh Required
	ResultInvalidResponse                    Result = 119  // Invalid Response
	ResultAmbiguousResponse                  Result = 120  // Ambiguous Response
	ResultTLSNotSupported                    Result = 121  // Tls Not Supported
	ResultIntermediateResponse               Result = 122  // Intermediate Response
	ResultUnknownType                        Result = 123  // Unknown Type
	ResultAuthorizationDenied                Result = 4096 // Authorization Denied
)

// Request is a ldap request.
type Request struct {
	ConnID     string
	LocalAddr  net.Addr
	RemoteAddr net.Addr
	ID         int64
	Packet     *ber.Packet
}

// ReadRequest reads a request from the connection.
func ReadRequest(conn net.Conn) (*Request, error) {
	_, p, err := ber.Parse(conn)
	if err != nil {
		return nil, err
	}
	fmt.Fprintf(os.Stdout, ">>>>> PACKET REQUEST\n%s\n---\n", hex.Dump(p.Bytes()))
	spew.Dump(p)
	p.PrettyPrint(os.Stdout, 0)
	fmt.Fprintf(os.Stdout, "<<<<< PACKET REQUEST\n")
	// check packet
	if len(p.Children) < 2 {
		return nil, ErrPacketHasInvalidNumberOfChildren
	}
	id, ok := p.Children[0].Value.(int64)
	if !ok {
		return nil, ErrPacketHasInvalidMessageID
	}
	if p.Children[1].Class != ber.ClassApplication {
		return nil, ErrPacketHasInvalidClass
	}
	return &Request{
		LocalAddr:  conn.LocalAddr(),
		RemoteAddr: conn.RemoteAddr(),
		ID:         id,
		Packet:     p.Children[1],
	}, nil
}

// ResponseWriter is the ldap response writer interface.
type ResponseWriter interface {
	WriteRaw([]byte) error
	WritePacket(*ber.Packet) error
	WriteMessage(*ber.Packet) error
	WriteResult(Application, Result, string, string, ...*ber.Packet) error
	WriteError(Application, error) error
}

// responseWriter wraps writing ldap messages.
type responseWriter struct {
	w  io.Writer
	id int64
}

// NewResponseWriter creates a new response writer for the writer and message
// id.
func NewResponseWriter(w io.Writer, id int64) ResponseWriter {
	return &responseWriter{
		w:  w,
		id: id,
	}
}

// WriteRaw writes raw bytes.
func (w *responseWriter) WriteRaw(buf []byte) error {
	// fmt.Fprintf(os.Stdout, ">>> WRITING\n%s\n<<<", hex.Dump(buf))
	if conn, ok := w.w.(interface {
		SetWriteDeadline(time.Time) error
	}); ok {
		if err := conn.SetWriteDeadline(time.Now().Add(3 * time.Second)); err != nil {
			return err
		}
	}
	_, err := w.w.Write(buf)
	return err
}

// WritePacket writes a packet.
func (w *responseWriter) WritePacket(p *ber.Packet) error {
	// ber.PrintPacket(p)
	return w.WriteRaw(p.Bytes())
}

// WriteMessage writes a ldap message.
func (w *responseWriter) WriteMessage(p *ber.Packet) error {
	return w.WritePacket(BuildMessagePacket(w.id, p))
}

// WriteResult writes a ldap result message.
func (w *responseWriter) WriteResult(app Application, result Result, matched, msg string, extra ...*ber.Packet) error {
	res := BuildResultPacket(app, result, matched, msg)
	for _, p := range extra {
		res.AppendChild(p)
	}
	return w.WriteMessage(res)
}

// WriteError writes a ldap result error message.
func (w *responseWriter) WriteError(app Application, err error) error {
	if e, ok := err.(*Error); ok {
		return w.WriteResult(app, e.Result, e.Matched, e.Message)
	}
	return w.WriteResult(app, ResultOperationsError, "", err.Error())
}

// BuildMessagePacket builds a ldap message packet.
func BuildMessagePacket(id int64, p *ber.Packet) *ber.Packet {
	msg := ber.NewPacket(
		ber.ClassUniversal,
		ber.TypeConstructed,
		ber.TagSequence,
		nil,
		"message",
	)
	msg.AppendChild(
		ber.NewInteger(
			ber.ClassUniversal,
			ber.TypePrimitive,
			ber.TagInteger,
			id,
			"id",
		),
	)
	msg.AppendChild(p)
	return msg
}

// BuildResultPacket builds a ldap result packet.
func BuildResultPacket(app Application, result Result, matched, msg string) *ber.Packet {
	p := ber.NewPacket(
		ber.ClassApplication,
		ber.TypeConstructed,
		ber.Tag(app),
		nil,
		app.String(),
	)
	p.AppendChild(
		ber.NewInteger(
			ber.ClassUniversal,
			ber.TypePrimitive,
			ber.TagEnumerated,
			int(result),
			"resultCode",
		),
	)
	p.AppendChild(
		ber.NewString(
			ber.ClassUniversal,
			ber.TypePrimitive,
			ber.TagOctetString,
			matched,
			"matchedDN",
		),
	)
	typ := "diagnosticMessage"
	if result != ResultSuccess {
		typ = "errorMessage"
	}
	p.AppendChild(
		ber.NewString(
			ber.ClassUniversal,
			ber.TypePrimitive,
			ber.TagOctetString,
			msg,
			typ,
		),
	)
	return p
}

// BuildExtendedNameValuePacket builds an extended name and value packet.
func BuildExtendedNameValuePacket(request bool, name ExtendedOp, value *ber.Packet) *ber.Packet {
	tag, typ := ber.Tag(0), "Request"
	if !request {
		typ = "Response"
	}
	if value != nil {
		tag = ber.TagEmbeddedPDV
	}
	p := ber.NewPacket(
		ber.ClassContext,
		ber.TypePrimitive,
		tag,
		name.String(),
		"extended"+typ,
	)
	if name != "" {
		_, _ = p.Data.Write([]byte(name))
	}
	if value != nil {
		p.AppendChild(value)
	}
	return p
}

// DoExtendedRequest performs an extended request against the provided context
// and client.
//
// Note: this is defined primarily for testing purposes, as the client does not
// provide any direct ability to send extended requests.
func DoExtendedRequest(ctx context.Context, cl *ldapclient.Client, req *ExtendedRequest) (*ExtendedResponse, error) {
	//	fmt.Fprintf(os.Stdout, "--------------------------- DoExtendedRequest\n")
	//	ber.PrintPacket(req.BuildPacket())
	//	fmt.Fprintf(os.Stdout, "--------------------------- DoExtendedRequest\n")
	msgCtx, err := cl.Do(req)
	if err != nil {
		return nil, err
	}
	defer cl.FinishMessage(msgCtx)
	p, err := cl.ReadPacket(msgCtx)
	if err != nil {
		return nil, err
	}
	if err := ldapclient.GetLDAPError(p); err != nil {
		return nil, err
	}
	if len(p.Children) != 2 {
		return nil, fmt.Errorf("invalid extended response (len=%d)", len(p.Children))
	}
	if p.Children[1].Tag != ApplicationExtendedResponse.Tag() {
		return nil, fmt.Errorf("invalid extended response tag %d", p.Children[1].Tag)
	}
	n := len(p.Children[1].Children)
	if n != 3 && n != 4 {
		return nil, fmt.Errorf("invalid extended response children (len=%d)", n)
	}
	result := Result(readInt64(p.Children[1].Children[0]))
	matched := readString(p.Children[1].Children[1])
	var value *ber.Packet
	if n == 4 {
		if p.Children[1].Children[3].Tag != ber.TagEmbeddedPDV {
			return nil, fmt.Errorf("extended response value is not embedded pdv (tag=%d)", p.Children[1].Children[3].Tag)
		}
		_, value, err = ber.Parse(p.Children[1].Children[3].Data)
		if err != nil {
			return nil, fmt.Errorf("unable to read extended response value: %v", err)
		}
	}
	return &ExtendedResponse{
		Result:    result,
		MatchedDN: matched,
		Value:     value,
	}, nil
}

func readInt64(p *ber.Packet) int64 {
	i, _ := p.Value.(int64)
	return i
}

func readString(p *ber.Packet) string {
	s, _ := p.Value.(string)
	return s
}

func readBool(p *ber.Packet) bool {
	b, _ := p.Value.(bool)
	return b
}

func readStringSlice(p *ber.Packet) []string {
	return nil
}

func readData(p *ber.Packet) []byte {
	if p.Data != nil {
		return p.Data.Bytes()
	}
	return nil
}
