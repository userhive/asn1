package ldapclient

import (
	"bytes"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/userhive/asn1/ber"
	"github.com/userhive/asn1/ldap/control"
)

func TestUnresponsiveConnection(t *testing.T) {
	t.Parallel()
	// The do-nothing server that accepts requests and does nothing
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	}))
	defer ts.Close()
	c, err := net.Dial(ts.Listener.Addr().Network(), ts.Listener.Addr().String())
	if err != nil {
		t.Fatalf("error connecting to localhost tcp: %v", err)
	}
	// Create an Ldap connection
	cl := NewClient(c, false)
	cl.SetTimeout(time.Millisecond)
	cl.Start()
	defer cl.Close()
	// Mock a packet
	p := ber.NewPacket(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Request")
	p.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, cl.nextMessageID(), "MessageID"))
	bindRequest := ber.NewPacket(ber.ClassApplication, ber.TypeConstructed, ApplicationBindRequest.Tag(), nil, "Bind Request")
	bindRequest.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 3, "Version"))
	p.AppendChild(bindRequest)
	// Send packet and test response
	msgCtx, err := cl.SendMessage(p)
	if err != nil {
		t.Fatalf("error sending message: %v", err)
	}
	defer cl.FinishMessage(msgCtx)
	res, ok := <-msgCtx.responses
	if !ok {
		t.Fatalf("no PacketResponse in response channel")
	}
	p, err = res.ReadPacket()
	if err == nil {
		t.Fatalf("expected timeout error")
	}
	if err.Error() != "ldap: connection timed out" {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestFinishMessage tests that we do not enter deadlock when a goroutine makes
// a request but does not handle all responses from the server.
func TestFinishMessage(t *testing.T) {
	t.Parallel()
	ptc := newPacketTranslatorConn()
	defer ptc.Close()
	cl := NewClient(ptc, false)
	cl.Start()
	// Test sending 5 different requests in series. Ensure that we can
	// get a response packet from the underlying connection and also
	// ensure that we can gracefully ignore unhandled responses.
	for i := 0; i < 5; i++ {
		t.Logf("serial request %d", i)
		// Create a message and make sure we can receive responses.
		msgCtx := testSendRequest(t, ptc, cl)
		testReceiveResponse(t, ptc, msgCtx)
		// Send a few unhandled responses and finish the message.
		testSendUnhandledResponsesAndFinish(t, ptc, cl, msgCtx, 5)
		t.Logf("serial request %d done", i)
	}
	// Test sending 5 different requests in parallel.
	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			t.Logf("parallel request %d", i)
			// Create a message and make sure we can receive responses.
			msgCtx := testSendRequest(t, ptc, cl)
			testReceiveResponse(t, ptc, msgCtx)
			// Send a few unhandled responses and finish the message.
			testSendUnhandledResponsesAndFinish(t, ptc, cl, msgCtx, 5)
			t.Logf("parallel request %d done", i)
		}(i)
	}
	wg.Wait()
	// We cannot run Close() in a defer because t.FailNow() will run it and
	// it will block if the processMessage Loop is in a deadlock.
	cl.Close()
}

func testSendRequest(t *testing.T, ptc *packetTranslatorConn, cl *Client) (msgCtx *MessageContext) {
	var msgID int64
	runWithTimeout(t, time.Second, func() {
		msgID = cl.nextMessageID()
	})
	req := ber.NewPacket(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Request")
	req.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, msgID, "MessageID"))
	var err error
	runWithTimeout(t, time.Second, func() {
		msgCtx, err = cl.SendMessage(req)
		if err != nil {
			t.Fatalf("unable to send request message: %s", err)
		}
	})
	// We should now be able to get this request packet out from the other
	// side.
	runWithTimeout(t, time.Second, func() {
		if _, err = ptc.ReceiveRequest(); err != nil {
			t.Fatalf("unable to receive request packet: %s", err)
		}
	})
	return msgCtx
}

func testReceiveResponse(t *testing.T, ptc *packetTranslatorConn, msgCtx *MessageContext) {
	// Send a mock response packet.
	res := ber.NewPacket(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Response")
	res.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, msgCtx.id, "MessageID"))
	runWithTimeout(t, time.Second, func() {
		if err := ptc.SendResponse(res); err != nil {
			t.Fatalf("unable to send response packet: %s", err)
		}
	})
	// We should be able to receive the packet from the connection.
	runWithTimeout(t, time.Second, func() {
		if _, ok := <-msgCtx.responses; !ok {
			t.Fatal("response channel closed")
		}
	})
}

func testSendUnhandledResponsesAndFinish(t *testing.T, ptc *packetTranslatorConn, cl *Client, msgCtx *MessageContext, numResponses int) {
	// Send a mock response packet.
	res := ber.NewPacket(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Response")
	res.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, msgCtx.id, "MessageID"))
	// Send extra responses but do not attempt to receive them on the
	// client side.
	for i := 0; i < numResponses; i++ {
		runWithTimeout(t, time.Second, func() {
			if err := ptc.SendResponse(res); err != nil {
				t.Fatalf("unable to send response packet: %s", err)
			}
		})
	}
	// Finally, attempt to finish this message.
	runWithTimeout(t, time.Second, func() {
		cl.FinishMessage(msgCtx)
	})
}

func runWithTimeout(t *testing.T, timeout time.Duration, f func()) {
	done := make(chan struct{})
	go func() {
		f()
		close(done)
	}()
	select {
	case <-done: // Success!
	case <-time.After(timeout):
		_, file, line, _ := runtime.Caller(1)
		t.Fatalf("%s:%d timed out", file, line)
	}
}

// packetTranslatorConn is a helpful type which can be used with various tests
// in this package. It implements the net.Conn interface to be used as an
// underlying connection for a *ldap.Conn. Most methods are no-ops but the
// Read() and Write() methods are able to translate ber-encoded packets for
// testing LDAP requests and responses.
//
// Test cases can simulate an LDAP server sending a response by calling the
// SendResponse() method with a ber-encoded LDAP response packet. Test cases
// can simulate an LDAP server receiving a request from a client by calling the
// ReceiveRequest() method which returns a ber-encoded LDAP request packet.
type packetTranslatorConn struct {
	lock         sync.Mutex
	isClosed     bool
	responseCond sync.Cond
	requestCond  sync.Cond
	responseBuf  bytes.Buffer
	requestBuf   bytes.Buffer
}

var errPacketTranslatorConnClosed = errors.New("connection closed")

func newPacketTranslatorConn() *packetTranslatorConn {
	conn := &packetTranslatorConn{}
	conn.responseCond = sync.Cond{L: &conn.lock}
	conn.requestCond = sync.Cond{L: &conn.lock}
	return conn
}

// Read is called by the reader() loop to receive response packets. It will
// block until there are more packet bytes available or this connection is
// closed.
func (c *packetTranslatorConn) Read(b []byte) (n int, err error) {
	c.lock.Lock()
	defer c.lock.Unlock()
	for !c.isClosed {
		// Attempt to read data from the response buffer. If it fails
		// with an EOF, wait and try again.
		n, err = c.responseBuf.Read(b)
		if err != io.EOF {
			return n, err
		}
		c.responseCond.Wait()
	}
	return 0, errPacketTranslatorConnClosed
}

// SendResponse writes the given response packet to the response buffer for
// this connection, signalling any goroutine waiting to read a response.
func (c *packetTranslatorConn) SendResponse(p *ber.Packet) error {
	c.lock.Lock()
	defer c.lock.Unlock()
	if c.isClosed {
		return errPacketTranslatorConnClosed
	}
	// Signal any goroutine waiting to read a response.
	defer c.responseCond.Broadcast()
	// Writes to the buffer should always succeed.
	c.responseBuf.Write(p.Bytes())
	return nil
}

// Write is called by the processMessages() loop to send request packets.
func (c *packetTranslatorConn) Write(b []byte) (n int, err error) {
	c.lock.Lock()
	defer c.lock.Unlock()
	if c.isClosed {
		return 0, errPacketTranslatorConnClosed
	}
	// Signal any goroutine waiting to read a request.
	defer c.requestCond.Broadcast()
	// Writes to the buffer should always succeed.
	return c.requestBuf.Write(b)
}

// ReceiveRequest attempts to read a request packet from this connection. It
// will block until it is able to read a full request packet or until this
// connection is closed.
func (c *packetTranslatorConn) ReceiveRequest() (*ber.Packet, error) {
	c.lock.Lock()
	defer c.lock.Unlock()
	for !c.isClosed {
		// Attempt to parse a request packet from the request buffer.
		// If it fails with an unexpected EOF, wait and try again.
		r := bytes.NewBuffer(c.requestBuf.Bytes())
		_, p, err := ber.Parse(r)
		switch err {
		case io.EOF, io.ErrUnexpectedEOF, ber.ErrUnexpectedEOF:
			c.requestCond.Wait()
		case nil:
			// Advance the request buffer by the number of bytes
			// read to decode the request packet.
			c.requestBuf.Next(c.requestBuf.Len() - r.Len())
			return p, nil
		default:
			return nil, err
		}
	}
	return nil, errPacketTranslatorConnClosed
}

// Close closes this connection causing Read() and Write() calls to fail.
func (c *packetTranslatorConn) Close() error {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.isClosed = true
	c.responseCond.Broadcast()
	c.requestCond.Broadcast()
	return nil
}

func (c *packetTranslatorConn) LocalAddr() net.Addr {
	return (*net.TCPAddr)(nil)
}

func (c *packetTranslatorConn) RemoteAddr() net.Addr {
	return (*net.TCPAddr)(nil)
}

func (c *packetTranslatorConn) SetDeadline(t time.Time) error {
	return nil
}

func (c *packetTranslatorConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (c *packetTranslatorConn) SetWriteDeadline(t time.Time) error {
	return nil
}

// TestNilPacket tests that nil packets don't cause a panic.
func TestNilPacket(t *testing.T) {
	t.Parallel()
	// Test for nil packet
	err := GetLDAPError(nil)
	if !IsErrorWithCode(err, ErrorUnexpectedResponse) {
		t.Errorf("Should have an 'ErrorUnexpectedResponse' error in nil packets, got: %v", err)
	}
	// Test for nil result
	kids := []*ber.Packet{
		{},  // Unused
		nil, // Can't be nil
	}
	pack := &ber.Packet{Children: kids}
	err = GetLDAPError(pack)
	if !IsErrorWithCode(err, ErrorUnexpectedResponse) {
		t.Errorf("Should have an 'ErrorUnexpectedResponse' error in nil packets, got: %v", err)
	}
}

// TestConnReadErr tests that an unexpected error reading from underlying
// connection bubbles up to the goroutine which makes a request.
func TestConnReadErr(t *testing.T) {
	t.Parallel()
	conn := &signalErrConn{
		signals: make(chan error),
	}
	cl := NewClient(conn, false)
	cl.Start()
	// Make a dummy search request.
	searchReq := NewSearchRequest("dc=example,dc=com", ScopeWholeSubtree, DerefAlways, 0, 0, false, "(objectClass=*)", nil)
	expectedError := errors.New("this is the error you are looking for")
	// Send the signal after a short amount of time.
	time.AfterFunc(10*time.Millisecond, func() { conn.signals <- expectedError })
	// This should block until the underlying conn gets the error signal
	// which should bubble up through the reader() goroutine, close the
	// connection, and
	_, err := cl.Search(searchReq)
	if err == nil || !strings.Contains(err.Error(), expectedError.Error()) {
		t.Errorf("not the expected error: %s", err)
	}
}

// TestGetLDAPError tests parsing of result with a error response.
func TestGetLDAPError(t *testing.T) {
	t.Parallel()
	diagnosticMessage := "Detailed error message"
	bindResponse := ber.NewPacket(ber.ClassApplication, ber.TypeConstructed, ApplicationBindResponse.Tag(), nil, "Bind Response")
	bindResponse.AppendChild(ber.NewPacket(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, int64(ResultInvalidCredentials), "resultCode"))
	bindResponse.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "dc=example,dc=org", "matchedDN"))
	bindResponse.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, diagnosticMessage, "diagnosticMessage"))
	p := ber.NewSequence("LDAPMessage")
	p.AppendChild(ber.NewPacket(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, int64(0), "messageID"))
	p.AppendChild(bindResponse)
	err := GetLDAPError(p)
	if err == nil {
		t.Errorf("Did not get error response")
	}
	ldapError := err.(*Error)
	if ldapError.ResultCode != ResultInvalidCredentials {
		t.Errorf("Got incorrect error code in LDAP error; got %v, expected %v", ldapError.ResultCode, ResultInvalidCredentials)
	}
	if ldapError.Err.Error() != diagnosticMessage {
		t.Errorf("Got incorrect error message in LDAP error; got %v, expected %v", ldapError.Err.Error(), diagnosticMessage)
	}
}

// TestGetLDAPErrorSuccess tests parsing of a result with no error (resultCode == 0).
func TestGetLDAPErrorSuccess(t *testing.T) {
	t.Parallel()
	bindResponse := ber.NewPacket(ber.ClassApplication, ber.TypeConstructed, ApplicationBindResponse.Tag(), nil, "Bind Response")
	bindResponse.AppendChild(ber.NewPacket(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, int64(0), "resultCode"))
	bindResponse.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "matchedDN"))
	bindResponse.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "diagnosticMessage"))
	p := ber.NewSequence("LDAPMessage")
	p.AppendChild(ber.NewPacket(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, int64(0), "messageID"))
	p.AppendChild(bindResponse)
	err := GetLDAPError(p)
	if err != nil {
		t.Errorf("Successful responses should not produce an error, but got: %v", err)
	}
}

// signalErrConn is a helpful type used with TestConnReadErr. It implements the
// net.Conn interface to be used as a connection for the test. Most methods are
// no-ops but the Read() method blocks until it receives a signal which it
// returns as an error.
type signalErrConn struct {
	signals chan error
}

// Read blocks until an error is sent on the internal signals channel. That
// error is returned.
func (c *signalErrConn) Read(b []byte) (n int, err error) {
	return 0, <-c.signals
}

func (c *signalErrConn) Write(b []byte) (n int, err error) {
	return len(b), nil
}

func (c *signalErrConn) Close() error {
	close(c.signals)
	return nil
}

func (c *signalErrConn) LocalAddr() net.Addr {
	return (*net.TCPAddr)(nil)
}

func (c *signalErrConn) RemoteAddr() net.Addr {
	return (*net.TCPAddr)(nil)
}

func (c *signalErrConn) SetDeadline(t time.Time) error {
	return nil
}

func (c *signalErrConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (c *signalErrConn) SetWriteDeadline(t time.Time) error {
	return nil
}

const ldapServer = "ldap://ldap.itd.umich.edu:389"
const ldapsServer = "ldaps://ldap.itd.umich.edu:636"
const baseDN = "dc=umich,dc=edu"

func testFilters() []string {
	return []string{
		"(cn=cis-fac)",
		"(&(owner=*)(cn=cis-fac))",
		"(&(objectclass=rfc822mailgroup)(cn=*Computer*))",
		"(&(objectclass=rfc822mailgroup)(cn=*Mathematics*))",
	}
}

var attributes = []string{
	"cn",
	"description",
}

func TestUnsecureDialURL(t *testing.T) {
	t.Parallel()
	l, err := DialURL(ldapServer)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
}

func TestSecureDialURL(t *testing.T) {
	t.Parallel()
	l, err := DialURL(ldapsServer, DialWithTLSConfig(&tls.Config{InsecureSkipVerify: true}))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
}

func TestStartTLS(t *testing.T) {
	t.Parallel()
	l, err := DialURL(ldapServer)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	err = l.StartTLS(&tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
}

func TestTLSConnectionState(t *testing.T) {
	t.Parallel()
	l, err := DialURL(ldapServer)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	err = l.StartTLS(&tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	cs, ok := l.TLSConnectionState()
	if !ok {
		t.Errorf("TLSConnectionState returned ok == false; want true")
	}
	if cs.Version == 0 || !cs.HandshakeComplete {
		t.Errorf("ConnectionState = %#v; expected Version != 0 and HandshakeComplete = true", cs)
	}
}

func TestSearch(t *testing.T) {
	t.Parallel()
	l, err := DialURL(ldapServer)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	searchRequest := NewSearchRequest(
		baseDN,
		ScopeWholeSubtree, DerefAlways, 0, 0, false,
		testFilters()[0],
		attributes,
	)
	sr, err := l.Search(searchRequest)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("TestSearch: %s -> num of entries = %d", searchRequest.Filter, len(sr.Entries))
}

func TestSearchStartTLS(t *testing.T) {
	t.Parallel()
	l, err := DialURL(ldapServer)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	searchRequest := NewSearchRequest(
		baseDN,
		ScopeWholeSubtree, DerefAlways, 0, 0, false,
		testFilters()[0],
		attributes,
	)
	sr, err := l.Search(searchRequest)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("TestSearchStartTLS: %s -> num of entries = %d", searchRequest.Filter, len(sr.Entries))
	t.Log("TestSearchStartTLS: upgrading with startTLS")
	err = l.StartTLS(&tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	sr, err = l.Search(searchRequest)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("TestSearchStartTLS: %s -> num of entries = %d", searchRequest.Filter, len(sr.Entries))
}

func TestSearchWithPaging(t *testing.T) {
	t.Parallel()
	l, err := DialURL(ldapServer)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	err = l.UnauthenticatedBind("")
	if err != nil {
		t.Fatal(err)
	}
	searchRequest := NewSearchRequest(
		baseDN,
		ScopeWholeSubtree, DerefAlways, 0, 0, false,
		testFilters()[2],
		attributes,
	)
	sr, err := l.SearchWithPaging(searchRequest, 5)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("TestSearchWithPaging: %s -> num of entries = %d", searchRequest.Filter, len(sr.Entries))
	searchRequest = NewSearchRequest(
		baseDN,
		ScopeWholeSubtree, DerefAlways, 0, 0, false,
		testFilters()[2],
		attributes,
		control.NewPaging(5),
	)
	sr, err = l.SearchWithPaging(searchRequest, 5)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("TestSearchWithPaging: %s -> num of entries = %d", searchRequest.Filter, len(sr.Entries))
	searchRequest = NewSearchRequest(
		baseDN,
		ScopeWholeSubtree, DerefAlways, 0, 0, false,
		testFilters()[2],
		attributes,
		control.NewPaging(500),
	)
	sr, err = l.SearchWithPaging(searchRequest, 5)
	if err == nil {
		t.Fatal("expected an error when paging size in control in search request doesn't match size given in call, got none")
	}
}

func searchGoroutine(t *testing.T, cl *Client, results chan *SearchResult, i int) {
	searchRequest := NewSearchRequest(
		baseDN,
		ScopeWholeSubtree, DerefAlways, 0, 0, false,
		testFilters()[i],
		attributes,
	)
	sr, err := cl.Search(searchRequest)
	if err != nil {
		t.Error(err)
		results <- nil
		return
	}
	results <- sr
}

func testMultiGoroutineSearch(t *testing.T, TLS bool, startTLS bool) {
	var cl *Client
	var err error
	if TLS {
		cl, err = DialURL(ldapsServer, DialWithTLSConfig(&tls.Config{InsecureSkipVerify: true}))
		if err != nil {
			t.Fatal(err)
		}
		defer cl.Close()
	} else {
		cl, err = DialURL(ldapServer)
		if err != nil {
			t.Fatal(err)
		}
		defer cl.Close()
		if startTLS {
			t.Log("TestMultiGoroutineSearch: using StartTLS...")
			err := cl.StartTLS(&tls.Config{InsecureSkipVerify: true})
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	results := make([]chan *SearchResult, len(testFilters()))
	for i := range testFilters() {
		results[i] = make(chan *SearchResult)
		go searchGoroutine(t, cl, results[i], i)
	}
	for i := range testFilters() {
		sr := <-results[i]
		if sr == nil {
			t.Errorf("Did not receive results from goroutine for %q", testFilters()[i])
		} else {
			t.Logf("TestMultiGoroutineSearch(%d): %s -> num of entries = %d", i, testFilters()[i], len(sr.Entries))
		}
	}
}

func TestMultiGoroutineSearch(t *testing.T) {
	t.Parallel()
	testMultiGoroutineSearch(t, false, false)
	testMultiGoroutineSearch(t, true, true)
	testMultiGoroutineSearch(t, false, true)
}

func TestCompare(t *testing.T) {
	t.Parallel()
	l, err := DialURL(ldapServer)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	const dn = "cn=math mich,ou=User Groups,ou=Groups,dc=umich,dc=edu"
	const attribute = "cn"
	const value = "math mich"
	sr, err := l.Compare(dn, attribute, value)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("Compare result:", sr)
}

func TestMatchDNError(t *testing.T) {
	t.Parallel()
	l, err := DialURL(ldapServer)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	const wrongBase = "ou=roups,dc=umich,dc=edu"
	searchRequest := NewSearchRequest(
		wrongBase,
		ScopeWholeSubtree, DerefAlways, 0, 0, false,
		testFilters()[0],
		attributes,
	)
	_, err = l.Search(searchRequest)
	if err == nil {
		t.Fatal("Expected Error, got nil")
	}
	t.Log("TestMatchDNError:", err)
}

// TestNewEntry tests that repeated calls to NewEntry return the same value with the same input
func TestNewEntry(t *testing.T) {
	t.Parallel()
	dn := "testDN"
	attributes := map[string][]string{
		"alpha":   {"value"},
		"beta":    {"value"},
		"gamma":   {"value"},
		"delta":   {"value"},
		"epsilon": {"value"},
	}
	executedEntry := NewEntry(dn, attributes)
	iteration := 0
	for {
		if iteration == 100 {
			break
		}
		testEntry := NewEntry(dn, attributes)
		if !reflect.DeepEqual(executedEntry, testEntry) {
			t.Fatalf("subsequent calls to NewEntry did not yield the same result:\n\texpected:\n\t%v\n\tgot:\n\t%v\n", executedEntry, testEntry)
		}
		iteration = iteration + 1
	}
}

func TestGetAttributeValue(t *testing.T) {
	t.Parallel()
	dn := "testDN"
	attributes := map[string][]string{
		"Alpha":   {"value"},
		"bEta":    {"value"},
		"gaMma":   {"value"},
		"delTa":   {"value"},
		"epsiLon": {"value"},
	}
	entry := NewEntry(dn, attributes)
	if entry.GetAttributeValue("Alpha") != "value" {
		t.Errorf("failed to get attribute in original case")
	}
	if entry.GetEqualFoldAttributeValue("alpha") != "value" {
		t.Errorf("failed to get attribute in changed case")
	}
}
