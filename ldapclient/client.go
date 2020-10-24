package ldapclient

import (
	"bytes"
	"crypto/md5"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Azure/go-ntlmssp"
	"github.com/userhive/asn1/ber"
	"github.com/userhive/asn1/ldap/filter"
	"github.com/userhive/asn1/ldapclient/control"
)

// debugging type
//     - has a Printf method to write the debug output
type debugging bool

// Enable controls debugging mode.
func (debug *debugging) Enable(b bool) {
	*debug = debugging(b)
}

// Printf writes debug output.
func (debug debugging) Printf(format string, args ...interface{}) {
	if debug {
		log.Printf(format, args...)
	}
}

// PrintPacket dumps a packet.
func (debug debugging) PrintPacket(packet *ber.Packet) {
	if debug {
		packet.PrettyPrint(os.Stdout, 0)
	}
}

const (
	// MessageQuit causes the processMessages loop to exit
	MessageQuit = 0
	// MessageRequest sends a request to the server
	MessageRequest = 1
	// MessageResponse receives a response from the server
	MessageResponse = 2
	// MessageFinish indicates the client considers a particular message ID to be finished
	MessageFinish = 3
	// MessageTimeout indicates the client-specified timeout for a particular message ID has been reached
	MessageTimeout = 4
)

// PacketResponse contains the packet or error encountered reading a response
type PacketResponse struct {
	// Packet is the packet read from the server
	Packet *ber.Packet
	// Error is an error encountered while reading
	Error error
}

// ReadPacket returns the packet or an error
func (pr *PacketResponse) ReadPacket() (*ber.Packet, error) {
	if (pr == nil) || (pr.Packet == nil && pr.Error == nil) {
		return nil, NewError(ErrorNetwork, errors.New("ldap: could not retrieve response"))
	}
	return pr.Packet, pr.Error
}

type MessageContext struct {
	id int64
	// close(done) should only be called from FinishMessage()
	done chan struct{}
	// close(responses) should only be called from processMessages(), and only sent to from SendResponse()
	responses chan *PacketResponse
}

// SendResponse should only be called within the processMessages() loop which
// is also responsible for closing the responses channel.
func (msgCtx *MessageContext) SendResponse(packet *PacketResponse) {
	select {
	case msgCtx.responses <- packet:
		// Successfully sent packet to message handler.
	case <-msgCtx.done:
		// The request handler is done and will not receive more
		// packets.
	}
}

type messagePacket struct {
	Op        int
	MessageID int64
	Packet    *ber.Packet
	Context   *MessageContext
}
type SendMessageFlags uint

const (
	startTLS SendMessageFlags = 1 << iota
)

// Client is an ldap client client.
type Client struct {
	// requestTimeout is loaded atomically
	// so we need to ensure 64-bit alignment on 32-bit platforms.
	requestTimeout      int64
	conn                net.Conn
	isTLS               bool
	closing             uint32
	closeErr            atomic.Value
	isStartingTLS       bool
	Debug               debugging
	chanConfirm         chan struct{}
	messageContexts     map[int64]*MessageContext
	chanMessage         chan *messagePacket
	chanMessageID       chan int64
	wgClose             sync.WaitGroup
	outstandingRequests uint
	messageMutex        sync.Mutex
}

// DefaultTimeout is a package-level variable that sets the timeout value
// used for the Dial and DialTLS methods.
//
// WARNING: since this is a package-level variable, setting this value from
// multiple places will probably result in undesired behaviour.
var DefaultTimeout = 60 * time.Second

// DialOpt configures DialContext.
type DialOpt func(*DialContext)

// DialWithDialer updates net.Dialer in DialContext.
func DialWithDialer(d *net.Dialer) DialOpt {
	return func(dc *DialContext) {
		dc.d = d
	}
}

// DialWithTLSConfig updates tls.Config in DialContext.
func DialWithTLSConfig(tc *tls.Config) DialOpt {
	return func(dc *DialContext) {
		dc.tc = tc
	}
}

// DialContext contains necessary parameters to dial the given ldap URL.
type DialContext struct {
	d  *net.Dialer
	tc *tls.Config
}

func (dc *DialContext) dial(u *url.URL) (net.Conn, error) {
	if u.Scheme == "ldapi" {
		if u.Path == "" || u.Path == "/" {
			u.Path = "/var/run/slapd/ldapi"
		}
		return dc.d.Dial("unix", u.Path)
	}
	host, port, err := net.SplitHostPort(u.Host)
	if err != nil {
		// we assume that error is due to missing port
		host = u.Host
		port = ""
	}
	switch u.Scheme {
	case "ldap":
		if port == "" {
			port = "389"
		}
		return dc.d.Dial("tcp", net.JoinHostPort(host, port))
	case "ldaps":
		if port == "" {
			port = "636"
		}
		return tls.DialWithDialer(dc.d, "tcp", net.JoinHostPort(host, port), dc.tc)
	}
	return nil, fmt.Errorf("Unknown scheme '%s'", u.Scheme)
}

// Dial connects to the given address on the given network using net.Dial
// and then returns a new Client for the connection.
// @deprecated Use DialURL instead.
func Dial(network, addr string) (*Client, error) {
	c, err := net.DialTimeout(network, addr, DefaultTimeout)
	if err != nil {
		return nil, NewError(ErrorNetwork, err)
	}
	conn := NewClient(c, false)
	conn.Start()
	return conn, nil
}

// DialTLS connects to the given address on the given network using tls.Dial
// and then returns a new Client for the connection.
// @deprecated Use DialURL instead.
func DialTLS(network, addr string, config *tls.Config) (*Client, error) {
	c, err := tls.DialWithDialer(&net.Dialer{Timeout: DefaultTimeout}, network, addr, config)
	if err != nil {
		return nil, NewError(ErrorNetwork, err)
	}
	conn := NewClient(c, true)
	conn.Start()
	return conn, nil
}

// DialURL connects to the given ldap URL.
// The following schemas are supported: ldap://, ldaps://, ldapi://.
// On success a new Client for the connection is returned.
func DialURL(addr string, opts ...DialOpt) (*Client, error) {
	u, err := url.Parse(addr)
	if err != nil {
		return nil, NewError(ErrorNetwork, err)
	}
	var dc DialContext
	for _, opt := range opts {
		opt(&dc)
	}
	if dc.d == nil {
		dc.d = &net.Dialer{Timeout: DefaultTimeout}
	}
	c, err := dc.dial(u)
	if err != nil {
		return nil, NewError(ErrorNetwork, err)
	}
	conn := NewClient(c, u.Scheme == "ldaps")
	conn.Start()
	return conn, nil
}

// NewClient returns a new Client using conn for network I/O.
func NewClient(conn net.Conn, isTLS bool) *Client {
	return &Client{
		conn:            conn,
		chanConfirm:     make(chan struct{}),
		chanMessageID:   make(chan int64),
		chanMessage:     make(chan *messagePacket, 10),
		messageContexts: map[int64]*MessageContext{},
		requestTimeout:  0,
		isTLS:           isTLS,
	}
}

// Start initializes goroutines to read responses and process messages
func (cl *Client) Start() {
	cl.wgClose.Add(1)
	go cl.reader()
	go cl.processMessages()
}

// IsClosing returns whether or not we're currently closing.
func (cl *Client) IsClosing() bool {
	return atomic.LoadUint32(&cl.closing) == 1
}

// setClosing sets the closing value to true
func (cl *Client) setClosing() bool {
	return atomic.CompareAndSwapUint32(&cl.closing, 0, 1)
}

// Close closes the connection.
func (cl *Client) Close() {
	cl.messageMutex.Lock()
	defer cl.messageMutex.Unlock()
	if cl.setClosing() {
		cl.Debug.Printf("Sending quit message and waiting for confirmation")
		cl.chanMessage <- &messagePacket{Op: MessageQuit}
		<-cl.chanConfirm
		close(cl.chanMessage)
		cl.Debug.Printf("Closing network connection")
		if err := cl.conn.Close(); err != nil {
			log.Println(err)
		}
		cl.wgClose.Done()
	}
	cl.wgClose.Wait()
}

// SetTimeout sets the time after a request is sent that a MessageTimeout triggers
func (cl *Client) SetTimeout(timeout time.Duration) {
	if timeout > 0 {
		atomic.StoreInt64(&cl.requestTimeout, int64(timeout))
	}
}

// Returns the next available messageID
func (cl *Client) nextMessageID() int64 {
	if messageID, ok := <-cl.chanMessageID; ok {
		return messageID
	}
	return 0
}

// StartTLS sends the command to start a TLS session and then creates a new TLS Client
func (cl *Client) StartTLS(config *tls.Config) error {
	if cl.isTLS {
		return NewError(ErrorNetwork, errors.New("ldap: already encrypted"))
	}
	packet := ber.NewPacket(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Request")
	packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, cl.nextMessageID(), "MessageID"))
	request := ber.NewPacket(ber.ClassApplication, ber.TypeConstructed, ApplicationExtendedRequest.Tag(), nil, "Start TLS")
	request.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, 0, "1.3.6.1.4.1.1466.20037", "TLS Extended Command"))
	packet.AppendChild(request)
	cl.Debug.PrintPacket(packet)
	msgCtx, err := cl.SendMessageWithFlags(packet, startTLS)
	if err != nil {
		return err
	}
	defer cl.FinishMessage(msgCtx)
	cl.Debug.Printf("%d: waiting for response", msgCtx.id)
	packetResponse, ok := <-msgCtx.responses
	if !ok {
		return NewError(ErrorNetwork, errors.New("ldap: response channel closed"))
	}
	packet, err = packetResponse.ReadPacket()
	cl.Debug.Printf("%d: got response %p", msgCtx.id, packet)
	if err != nil {
		return err
	}
	if cl.Debug {
		if err := AddLDAPDescriptions(packet); err != nil {
			cl.Close()
			return err
		}
		cl.Debug.PrintPacket(packet)
	}
	if err := GetLDAPError(packet); err == nil {
		conn := tls.Client(cl.conn, config)
		if connErr := conn.Handshake(); connErr != nil {
			cl.Close()
			return NewError(ErrorNetwork, fmt.Errorf("TLS handshake failed (%v)", connErr))
		}
		cl.isTLS = true
		cl.conn = conn
	} else {
		return err
	}
	go cl.reader()
	return nil
}

// TLSConnectionState returns the client's TLS connection state.
// The return values are their zero values if StartTLS did
// not succeed.
func (cl *Client) TLSConnectionState() (state tls.ConnectionState, ok bool) {
	tc, ok := cl.conn.(*tls.Conn)
	if !ok {
		return
	}
	return tc.ConnectionState(), true
}

func (cl *Client) SendMessage(packet *ber.Packet) (*MessageContext, error) {
	return cl.SendMessageWithFlags(packet, 0)
}

func (cl *Client) SendMessageWithFlags(packet *ber.Packet, flags SendMessageFlags) (*MessageContext, error) {
	if cl.IsClosing() {
		return nil, NewError(ErrorNetwork, errors.New("ldap: connection closed"))
	}
	cl.messageMutex.Lock()
	cl.Debug.Printf("flags&startTLS = %d", flags&startTLS)
	if cl.isStartingTLS {
		cl.messageMutex.Unlock()
		return nil, NewError(ErrorNetwork, errors.New("ldap: connection is in startls phase"))
	}
	if flags&startTLS != 0 {
		if cl.outstandingRequests != 0 {
			cl.messageMutex.Unlock()
			return nil, NewError(ErrorNetwork, errors.New("ldap: cannot StartTLS with outstanding requests"))
		}
		cl.isStartingTLS = true
	}
	cl.outstandingRequests++
	cl.messageMutex.Unlock()
	responses := make(chan *PacketResponse)
	messageID := packet.Children[0].Value.(int64)
	message := &messagePacket{
		Op:        MessageRequest,
		MessageID: messageID,
		Packet:    packet,
		Context: &MessageContext{
			id:        messageID,
			done:      make(chan struct{}),
			responses: responses,
		},
	}
	if !cl.sendProcessMessage(message) {
		if cl.IsClosing() {
			return nil, NewError(ErrorNetwork, errors.New("ldap: connection closed"))
		}
		return nil, NewError(ErrorNetwork, errors.New("ldap: could not send message for unknown reason"))
	}
	return message.Context, nil
}

func (cl *Client) FinishMessage(msgCtx *MessageContext) {
	close(msgCtx.done)
	if cl.IsClosing() {
		return
	}
	cl.messageMutex.Lock()
	cl.outstandingRequests--
	if cl.isStartingTLS {
		cl.isStartingTLS = false
	}
	cl.messageMutex.Unlock()
	message := &messagePacket{
		Op:        MessageFinish,
		MessageID: msgCtx.id,
	}
	cl.sendProcessMessage(message)
}

func (cl *Client) sendProcessMessage(message *messagePacket) bool {
	cl.messageMutex.Lock()
	defer cl.messageMutex.Unlock()
	if cl.IsClosing() {
		return false
	}
	cl.chanMessage <- message
	return true
}

func (cl *Client) processMessages() {
	defer func() {
		if err := recover(); err != nil {
			log.Printf("ldap: recovered panic in processMessages: %v", err)
		}
		for messageID, msgCtx := range cl.messageContexts {
			// If we are closing due to an error, inform anyone who
			// is waiting about the error.
			if cl.IsClosing() && cl.closeErr.Load() != nil {
				msgCtx.SendResponse(&PacketResponse{Error: cl.closeErr.Load().(error)})
			}
			cl.Debug.Printf("Closing channel for MessageID %d", messageID)
			close(msgCtx.responses)
			delete(cl.messageContexts, messageID)
		}
		close(cl.chanMessageID)
		close(cl.chanConfirm)
	}()
	var messageID int64 = 1
	for {
		select {
		case cl.chanMessageID <- messageID:
			messageID++
		case message := <-cl.chanMessage:
			switch message.Op {
			case MessageQuit:
				cl.Debug.Printf("Shutting down - quit message received")
				return
			case MessageRequest:
				// Add to message list and write to network
				cl.Debug.Printf("Sending message %d", message.MessageID)
				buf := message.Packet.Bytes()
				_, err := cl.conn.Write(buf)
				if err != nil {
					cl.Debug.Printf("Error Sending Message: %s", err.Error())
					message.Context.SendResponse(&PacketResponse{Error: fmt.Errorf("unable to send request: %s", err)})
					close(message.Context.responses)
					break
				}
				// Only add to messageContexts if we were able to
				// successfully write the message.
				cl.messageContexts[message.MessageID] = message.Context
				// Add timeout if defined
				requestTimeout := time.Duration(atomic.LoadInt64(&cl.requestTimeout))
				if requestTimeout > 0 {
					go func() {
						defer func() {
							if err := recover(); err != nil {
								log.Printf("ldap: recovered panic in RequestTimeout: %v", err)
							}
						}()
						time.Sleep(requestTimeout)
						timeoutMessage := &messagePacket{
							Op:        MessageTimeout,
							MessageID: message.MessageID,
						}
						cl.sendProcessMessage(timeoutMessage)
					}()
				}
			case MessageResponse:
				cl.Debug.Printf("Receiving message %d", message.MessageID)
				if msgCtx, ok := cl.messageContexts[message.MessageID]; ok {
					msgCtx.SendResponse(&PacketResponse{message.Packet, nil})
				} else {
					log.Printf("Received unexpected message %d, %v", message.MessageID, cl.IsClosing())
					cl.Debug.PrintPacket(message.Packet)
				}
			case MessageTimeout:
				// Handle the timeout by closing the channel
				// All reads will return immediately
				if msgCtx, ok := cl.messageContexts[message.MessageID]; ok {
					cl.Debug.Printf("Receiving message timeout for %d", message.MessageID)
					msgCtx.SendResponse(&PacketResponse{message.Packet, errors.New("ldap: connection timed out")})
					delete(cl.messageContexts, message.MessageID)
					close(msgCtx.responses)
				}
			case MessageFinish:
				cl.Debug.Printf("Finished message %d", message.MessageID)
				if msgCtx, ok := cl.messageContexts[message.MessageID]; ok {
					delete(cl.messageContexts, message.MessageID)
					close(msgCtx.responses)
				}
			}
		}
	}
}

func (cl *Client) reader() {
	cleanstop := false
	defer func() {
		if err := recover(); err != nil {
			log.Printf("ldap: recovered panic in reader: %v", err)
		}
		if !cleanstop {
			cl.Close()
		}
	}()
	for {
		if cleanstop {
			cl.Debug.Printf("reader clean stopping (without closing the connection)")
			return
		}
		_, packet, err := ber.Parse(cl.conn)
		if err != nil {
			// A read error is expected here if we are closing the connection...
			if !cl.IsClosing() {
				cl.closeErr.Store(fmt.Errorf("unable to read LDAP response packet: %s", err))
				cl.Debug.Printf("reader error: %s", err)
			}
			return
		}
		if err := AddLDAPDescriptions(packet); err != nil {
			cl.Debug.Printf("descriptions error: %s", err)
		}
		if len(packet.Children) == 0 {
			cl.Debug.Printf("Received bad ldap packet")
			continue
		}
		cl.messageMutex.Lock()
		if cl.isStartingTLS {
			cleanstop = true
		}
		cl.messageMutex.Unlock()
		message := &messagePacket{
			Op:        MessageResponse,
			MessageID: packet.Children[0].Value.(int64),
			Packet:    packet,
		}
		if !cl.sendProcessMessage(message) {
			return
		}
	}
}

func (cl *Client) Do(req Request) (*MessageContext, error) {
	packet := ber.NewPacket(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Request")
	packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, cl.nextMessageID(), "MessageID"))
	if err := req.AppendTo(packet); err != nil {
		return nil, err
	}
	if cl.Debug {
		cl.Debug.PrintPacket(packet)
	}
	msgCtx, err := cl.SendMessage(packet)
	if err != nil {
		return nil, err
	}
	cl.Debug.Printf("%d: returning", msgCtx.id)
	return msgCtx, nil
}

func (cl *Client) ReadPacket(msgCtx *MessageContext) (*ber.Packet, error) {
	cl.Debug.Printf("%d: waiting for response", msgCtx.id)
	packetResponse, ok := <-msgCtx.responses
	if !ok {
		return nil, NewError(ErrorNetwork, errRespChanClosed)
	}
	packet, err := packetResponse.ReadPacket()
	cl.Debug.Printf("%d: got response %p", msgCtx.id, packet)
	if err != nil {
		return nil, err
	}
	if packet == nil {
		return nil, NewError(ErrorNetwork, errCouldNotRetMsg)
	}
	if cl.Debug {
		if err = AddLDAPDescriptions(packet); err != nil {
			return nil, err
		}
		cl.Debug.PrintPacket(packet)
	}
	return packet, nil
}

// SimpleBind performs the simple bind operation defined in the given request
func (cl *Client) SimpleBind(simpleBindRequest *SimpleBindRequest) (*SimpleBindResult, error) {
	if simpleBindRequest.Password == "" && !simpleBindRequest.AllowEmptyPassword {
		return nil, NewError(ErrorEmptyPassword, errors.New("ldap: empty password not allowed by the client"))
	}
	msgCtx, err := cl.Do(simpleBindRequest)
	if err != nil {
		return nil, err
	}
	defer cl.FinishMessage(msgCtx)
	packet, err := cl.ReadPacket(msgCtx)
	if err != nil {
		return nil, err
	}
	result := &SimpleBindResult{
		Controls: make([]control.Control, 0),
	}
	if len(packet.Children) == 3 {
		for _, child := range packet.Children[2].Children {
			decodedChild, decodeErr := control.Decode(child)
			if decodeErr != nil {
				return nil, fmt.Errorf("failed to decode child control: %s", decodeErr)
			}
			result.Controls = append(result.Controls, decodedChild)
		}
	}
	err = GetLDAPError(packet)
	return result, err
}

// Bind performs a bind with the given username and password.
//
// It does not allow unauthenticated bind (i.e. empty password). Use the UnauthenticatedBind method
// for that.
func (cl *Client) Bind(username, password string) error {
	req := &SimpleBindRequest{
		Username:           username,
		Password:           password,
		AllowEmptyPassword: false,
	}
	_, err := cl.SimpleBind(req)
	return err
}

// UnauthenticatedBind performs an unauthenticated bind.
//
// A username may be provided for trace (e.g. logging) purpose only, but it is normally not
// authenticated or otherwise validated by the LDAP server.
//
// See https://tools.ietf.org/html/rfc4513#section-5.1.2 .
// See https://tools.ietf.org/html/rfc4513#section-6.3.1 .
func (cl *Client) UnauthenticatedBind(username string) error {
	req := &SimpleBindRequest{
		Username:           username,
		Password:           "",
		AllowEmptyPassword: true,
	}
	_, err := cl.SimpleBind(req)
	return err
}

// MD5Bind performs a digest-md5 bind with the given host, username and password.
func (cl *Client) MD5Bind(host, username, password string) error {
	req := &DigestMD5BindRequest{
		Host:     host,
		Username: username,
		Password: password,
	}
	_, err := cl.DigestMD5Bind(req)
	return err
}

// DigestMD5Bind performs the digest-md5 bind operation defined in the given request
func (cl *Client) DigestMD5Bind(digestMD5BindRequest *DigestMD5BindRequest) (*DigestMD5BindResult, error) {
	if digestMD5BindRequest.Password == "" {
		return nil, NewError(ErrorEmptyPassword, errors.New("ldap: empty password not allowed by the client"))
	}
	msgCtx, err := cl.Do(digestMD5BindRequest)
	if err != nil {
		return nil, err
	}
	defer cl.FinishMessage(msgCtx)
	packet, err := cl.ReadPacket(msgCtx)
	if err != nil {
		return nil, err
	}
	cl.Debug.Printf("%d: got response %p", msgCtx.id, packet)
	if cl.Debug {
		if err = AddLDAPDescriptions(packet); err != nil {
			return nil, err
		}
		packet.PrettyPrint(os.Stdout, 0)
	}
	result := &DigestMD5BindResult{
		Controls: make([]control.Control, 0),
	}
	var params map[string]string
	if len(packet.Children) == 2 {
		if len(packet.Children[1].Children) == 4 {
			child := packet.Children[1].Children[0]
			if child.Tag != ber.TagEnumerated {
				return result, GetLDAPError(packet)
			}
			if child.Value.(int64) != 14 {
				return result, GetLDAPError(packet)
			}
			child = packet.Children[1].Children[3]
			if child.Tag != ber.TagObjectDescriptor {
				return result, GetLDAPError(packet)
			}
			if child.Data == nil {
				return result, GetLDAPError(packet)
			}
			data, _ := ioutil.ReadAll(child.Data)
			params, err = parseParams(string(data))
			if err != nil {
				return result, fmt.Errorf("parsing digest-challenge: %s", err)
			}
		}
	}
	if params != nil {
		resp := computeResponse(
			params,
			"ldap/"+strings.ToLower(digestMD5BindRequest.Host),
			digestMD5BindRequest.Username,
			digestMD5BindRequest.Password,
		)
		packet = ber.NewPacket(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Request")
		packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, cl.nextMessageID(), "MessageID"))
		request := ber.NewPacket(ber.ClassApplication, ber.TypeConstructed, ApplicationBindRequest.Tag(), nil, "Bind Request")
		request.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 3, "Version"))
		request.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "User Name"))
		auth := ber.NewPacket(ber.ClassContext, ber.TypeConstructed, 3, "", "authentication")
		auth.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "DIGEST-MD5", "SASL Mech"))
		auth.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, resp, "Credentials"))
		request.AppendChild(auth)
		packet.AppendChild(request)
		msgCtx, err = cl.SendMessage(packet)
		if err != nil {
			return nil, fmt.Errorf("send message: %s", err)
		}
		defer cl.FinishMessage(msgCtx)
		packetResponse, ok := <-msgCtx.responses
		if !ok {
			return nil, NewError(ErrorNetwork, errors.New("ldap: response channel closed"))
		}
		packet, err = packetResponse.ReadPacket()
		cl.Debug.Printf("%d: got response %p", msgCtx.id, packet)
		if err != nil {
			return nil, fmt.Errorf("read packet: %s", err)
		}
	}
	err = GetLDAPError(packet)
	return result, err
}

// Compare checks to see if the attribute of the dn matches value. Returns true if it does otherwise
// false with any error that occurs if any.
func (cl *Client) Compare(dn, attribute, value string) (bool, error) {
	msgCtx, err := cl.Do(&CompareRequest{
		DN:        dn,
		Attribute: attribute,
		Value:     value,
	})
	if err != nil {
		return false, err
	}
	defer cl.FinishMessage(msgCtx)
	packet, err := cl.ReadPacket(msgCtx)
	if err != nil {
		return false, err
	}
	if packet.Children[1].Tag == ApplicationCompareResponse.Tag() {
		err := GetLDAPError(packet)
		switch {
		case IsErrorWithCode(err, ResultCompareTrue):
			return true, nil
		case IsErrorWithCode(err, ResultCompareFalse):
			return false, nil
		default:
			return false, err
		}
	}
	return false, fmt.Errorf("unexpected Response: %d", packet.Children[1].Tag)
}

// Del executes the given delete request
func (cl *Client) Del(delRequest *DeleteRequest) error {
	msgCtx, err := cl.Do(delRequest)
	if err != nil {
		return err
	}
	defer cl.FinishMessage(msgCtx)
	packet, err := cl.ReadPacket(msgCtx)
	if err != nil {
		return err
	}
	if packet.Children[1].Tag == ApplicationDeleteResponse.Tag() {
		err := GetLDAPError(packet)
		if err != nil {
			return err
		}
	} else {
		log.Printf("Unexpected Response: %d", packet.Children[1].Tag)
	}
	return nil
}

// ModifyDN renames the given DN and optionally move to another base (when the "newSup" argument
// to NewModifyDNRequest() is not "").
func (cl *Client) ModifyDN(m *ModifyDNRequest) error {
	msgCtx, err := cl.Do(m)
	if err != nil {
		return err
	}
	defer cl.FinishMessage(msgCtx)
	packet, err := cl.ReadPacket(msgCtx)
	if err != nil {
		return err
	}
	if packet.Children[1].Tag == ApplicationModifyDNResponse.Tag() {
		err := GetLDAPError(packet)
		if err != nil {
			return err
		}
	} else {
		log.Printf("Unexpected Response: %d", packet.Children[1].Tag)
	}
	return nil
}

// Add performs the given AddRequest
func (cl *Client) Add(addRequest *AddRequest) error {
	msgCtx, err := cl.Do(addRequest)
	if err != nil {
		return err
	}
	defer cl.FinishMessage(msgCtx)
	packet, err := cl.ReadPacket(msgCtx)
	if err != nil {
		return err
	}
	if packet.Children[1].Tag == ApplicationAddResponse.Tag() {
		err := GetLDAPError(packet)
		if err != nil {
			return err
		}
	} else {
		log.Printf("Unexpected Response: %d", packet.Children[1].Tag)
	}
	return nil
}

// Modify performs the ModifyRequest
func (cl *Client) Modify(modifyRequest *ModifyRequest) error {
	msgCtx, err := cl.Do(modifyRequest)
	if err != nil {
		return err
	}
	defer cl.FinishMessage(msgCtx)
	packet, err := cl.ReadPacket(msgCtx)
	if err != nil {
		return err
	}
	if packet.Children[1].Tag == ApplicationModifyResponse.Tag() {
		err := GetLDAPError(packet)
		if err != nil {
			return err
		}
	} else {
		log.Printf("Unexpected Response: %d", packet.Children[1].Tag)
	}
	return nil
}

// PasswordModify performs the modification request
func (cl *Client) PasswordModify(passwordModifyRequest *PasswordModifyRequest) (*PasswordModifyResult, error) {
	msgCtx, err := cl.Do(passwordModifyRequest)
	if err != nil {
		return nil, err
	}
	defer cl.FinishMessage(msgCtx)
	packet, err := cl.ReadPacket(msgCtx)
	if err != nil {
		return nil, err
	}
	result := &PasswordModifyResult{}
	if packet.Children[1].Tag == ApplicationExtendedResponse.Tag() {
		err := GetLDAPError(packet)
		if err != nil {
			if IsErrorWithCode(err, ResultReferral) {
				for _, child := range packet.Children[1].Children {
					if child.Tag == 3 {
						result.Referral = child.Children[0].Value.(string)
					}
				}
			}
			return result, err
		}
	} else {
		return nil, NewError(ErrorUnexpectedResponse, fmt.Errorf("unexpected Response: %d", packet.Children[1].Tag))
	}
	extendedResponse := packet.Children[1]
	for _, child := range extendedResponse.Children {
		if child.Tag == 11 {
			_, passwordModifyResponseValue, err := ber.Parse(child.Data)
			if err != nil {
				return nil, err
			}
			if len(passwordModifyResponseValue.Children) == 1 {
				if passwordModifyResponseValue.Children[0].Tag == 0 {
					result.GeneratedPassword = string(passwordModifyResponseValue.Children[0].Data.Bytes())
				}
			}
		}
	}
	return result, nil
}

// ExternalBind performs SASL/EXTERNAL authentication.
//
// Use ldap.DialURL("ldapi://") to connect to the Unix socket before ExternalBind.
//
// See https://tools.ietf.org/html/rfc4422#appendix-A
func (cl *Client) ExternalBind() error {
	msgCtx, err := cl.Do(externalBindRequest)
	if err != nil {
		return err
	}
	defer cl.FinishMessage(msgCtx)
	packet, err := cl.ReadPacket(msgCtx)
	if err != nil {
		return err
	}
	return GetLDAPError(packet)
}

// NTLMBind performs an NTLMSSP Bind with the given domain, username and password
func (cl *Client) NTLMBind(domain, username, password string) error {
	req := &NTLMBindRequest{
		Domain:   domain,
		Username: username,
		Password: password,
	}
	_, err := cl.NTLMChallengeBind(req)
	return err
}

// NTLMBindWithHash performs an NTLM Bind with an NTLM hash instead of plaintext password (pass-the-hash)
func (cl *Client) NTLMBindWithHash(domain, username, hash string) error {
	req := &NTLMBindRequest{
		Domain:   domain,
		Username: username,
		Hash:     hash,
	}
	_, err := cl.NTLMChallengeBind(req)
	return err
}

// NTLMChallengeBind performs the NTLMSSP bind operation defined in the given request
func (cl *Client) NTLMChallengeBind(ntlmBindRequest *NTLMBindRequest) (*NTLMBindResult, error) {
	if ntlmBindRequest.Password == "" && ntlmBindRequest.Hash == "" {
		return nil, NewError(ErrorEmptyPassword, errors.New("ldap: empty password not allowed by the client"))
	}
	msgCtx, err := cl.Do(ntlmBindRequest)
	if err != nil {
		return nil, err
	}
	defer cl.FinishMessage(msgCtx)
	packet, err := cl.ReadPacket(msgCtx)
	if err != nil {
		return nil, err
	}
	cl.Debug.Printf("%d: got response %p", msgCtx.id, packet)
	if cl.Debug {
		if err = AddLDAPDescriptions(packet); err != nil {
			return nil, err
		}
		packet.PrettyPrint(os.Stdout, 0)
	}
	result := &NTLMBindResult{
		Controls: make([]control.Control, 0),
	}
	var ntlmsspChallenge []byte
	// now find the NTLM Response Message
	if len(packet.Children) == 2 {
		if len(packet.Children[1].Children) == 3 {
			child := packet.Children[1].Children[1]
			ntlmsspChallenge = child.ByteValue
			// Check to make sure we got the right message. It will always start with NTLMSSP
			if !bytes.Equal(ntlmsspChallenge[:7], []byte("NTLMSSP")) {
				return result, GetLDAPError(packet)
			}
			cl.Debug.Printf("%d: found ntlmssp challenge", msgCtx.id)
		}
	}
	if ntlmsspChallenge != nil {
		var err error
		var responseMessage []byte
		// generate a response message to the challenge with the given Username/Password if password is provided
		if ntlmBindRequest.Password != "" {
			responseMessage, err = ntlmssp.ProcessChallenge(ntlmsspChallenge, ntlmBindRequest.Username, ntlmBindRequest.Password)
		} else if ntlmBindRequest.Hash != "" {
			responseMessage, err = ntlmssp.ProcessChallengeWithHash(ntlmsspChallenge, ntlmBindRequest.Username, ntlmBindRequest.Hash)
		} else {
			err = fmt.Errorf("need a password or hash to generate reply")
		}
		if err != nil {
			return result, fmt.Errorf("parsing ntlm-challenge: %s", err)
		}
		packet = ber.NewPacket(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Request")
		packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, cl.nextMessageID(), "MessageID"))
		request := ber.NewPacket(ber.ClassApplication, ber.TypeConstructed, ApplicationBindRequest.Tag(), nil, "Bind Request")
		request.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 3, "Version"))
		request.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "User Name"))
		// append the challenge response message as a TagEmbeddedPDV BER value
		auth := ber.NewPacket(ber.ClassContext, ber.TypePrimitive, ber.TagEmbeddedPDV, responseMessage, "authentication")
		request.AppendChild(auth)
		packet.AppendChild(request)
		msgCtx, err = cl.SendMessage(packet)
		if err != nil {
			return nil, fmt.Errorf("send message: %s", err)
		}
		defer cl.FinishMessage(msgCtx)
		packetResponse, ok := <-msgCtx.responses
		if !ok {
			return nil, NewError(ErrorNetwork, errors.New("ldap: response channel closed"))
		}
		packet, err = packetResponse.ReadPacket()
		cl.Debug.Printf("%d: got response %p", msgCtx.id, packet)
		if err != nil {
			return nil, fmt.Errorf("read packet: %s", err)
		}
	}
	err = GetLDAPError(packet)
	return result, err
}

// SearchWithPaging accepts a search request and desired page size in order to execute LDAP queries to fulfill the
// search request. All paged LDAP query responses will be buffered and the final result will be returned atomically.
// The following four cases are possible given the arguments:
//  - given SearchRequest missing a control of type control.OIDPaging: we will add one with the desired paging size
//  - given SearchRequest contains a control of type control.OIDPaging that isn't actually a ControlPaging: fail without issuing any queries
//  - given SearchRequest contains a control of type control.OIDPaging with pagingSize equal to the size requested: no change to the search request
//  - given SearchRequest contains a control of type control.OIDPaging with pagingSize not equal to the size requested: fail without issuing any queries
// A requested pagingSize of 0 is interpreted as no limit by LDAP servers.
func (cl *Client) SearchWithPaging(searchRequest *SearchRequest, pagingSize uint32) (*SearchResult, error) {
	var pagingControl *control.ControlPaging
	c := control.Find(searchRequest.Controls, control.OIDPaging)
	if c == nil {
		pagingControl = control.NewControlPaging(pagingSize)
		searchRequest.Controls = append(searchRequest.Controls, pagingControl)
	} else {
		castControl, ok := c.(*control.ControlPaging)
		if !ok {
			return nil, fmt.Errorf("expected paging control to be of type *ControlPaging, got %v", c)
		}
		if castControl.PagingSize != pagingSize {
			return nil, fmt.Errorf("paging size given in search request (%d) conflicts with size given in search call (%d)", castControl.PagingSize, pagingSize)
		}
		pagingControl = castControl
	}
	searchResult := new(SearchResult)
	for {
		result, err := cl.Search(searchRequest)
		cl.Debug.Printf("Looking for Paging Control...")
		if err != nil {
			return searchResult, err
		}
		if result == nil {
			return searchResult, NewError(ErrorNetwork, errors.New("ldap: packet not received"))
		}
		for _, entry := range result.Entries {
			searchResult.Entries = append(searchResult.Entries, entry)
		}
		for _, referral := range result.Referrals {
			searchResult.Referrals = append(searchResult.Referrals, referral)
		}
		for _, control := range result.Controls {
			searchResult.Controls = append(searchResult.Controls, control)
		}
		cl.Debug.Printf("Looking for Paging Control...")
		pagingResult := control.Find(result.Controls, control.OIDPaging)
		if pagingResult == nil {
			pagingControl = nil
			cl.Debug.Printf("Could not find paging control.  Breaking...")
			break
		}
		cookie := pagingResult.(*control.ControlPaging).Cookie
		if len(cookie) == 0 {
			pagingControl = nil
			cl.Debug.Printf("Could not find cookie.  Breaking...")
			break
		}
		pagingControl.SetCookie(cookie)
	}
	if pagingControl != nil {
		cl.Debug.Printf("Abandoning Paging...")
		pagingControl.PagingSize = 0
		cl.Search(searchRequest)
	}
	return searchResult, nil
}

// Search performs the given search request
func (cl *Client) Search(searchRequest *SearchRequest) (*SearchResult, error) {
	msgCtx, err := cl.Do(searchRequest)
	if err != nil {
		return nil, err
	}
	defer cl.FinishMessage(msgCtx)
	result := &SearchResult{
		Entries:   make([]*Entry, 0),
		Referrals: make([]string, 0),
		Controls:  make([]control.Control, 0),
	}
	for {
		packet, err := cl.ReadPacket(msgCtx)
		if err != nil {
			return result, err
		}
		switch packet.Children[1].Tag {
		case 4:
			entry := new(Entry)
			entry.DN = packet.Children[1].Children[0].Value.(string)
			for _, child := range packet.Children[1].Children[1].Children {
				attr := new(EntryAttribute)
				attr.Name = child.Children[0].Value.(string)
				for _, value := range child.Children[1].Children {
					attr.Values = append(attr.Values, value.Value.(string))
					attr.ByteValues = append(attr.ByteValues, value.ByteValue)
				}
				entry.Attributes = append(entry.Attributes, attr)
			}
			result.Entries = append(result.Entries, entry)
		case 5:
			err := GetLDAPError(packet)
			if err != nil {
				return result, err
			}
			if len(packet.Children) == 3 {
				for _, child := range packet.Children[2].Children {
					decodedChild, err := control.Decode(child)
					if err != nil {
						return result, fmt.Errorf("failed to decode child control: %s", err)
					}
					result.Controls = append(result.Controls, decodedChild)
				}
			}
			return result, nil
		case 19:
			result.Referrals = append(result.Referrals, packet.Children[1].Children[0].Value.(string))
		}
	}
}

var (
	errRespChanClosed = errors.New("ldap: response channel closed")
	errCouldNotRetMsg = errors.New("ldap: could not retrieve message")
)

type Request interface {
	AppendTo(*ber.Packet) error
}

type RequestFunc func(*ber.Packet) error

func (f RequestFunc) AppendTo(p *ber.Packet) error {
	return f(p)
}

// Application is the ldap application type.
type Application int

func (app Application) String() string {
	return app.Tag().String()
}

func (app Application) Tag() ber.Tag {
	return ber.Tag(app)
}

// Application values.
const (
	ApplicationBindRequest           Application = 0
	ApplicationBindResponse          Application = 1
	ApplicationUnbindRequest         Application = 2
	ApplicationSearchRequest         Application = 3
	ApplicationSearchResultEntry     Application = 4
	ApplicationSearchResultDone      Application = 5
	ApplicationModifyRequest         Application = 6
	ApplicationModifyResponse        Application = 7
	ApplicationAddRequest            Application = 8
	ApplicationAddResponse           Application = 9
	ApplicationDeleteRequest         Application = 10
	ApplicationDeleteResponse        Application = 11
	ApplicationModifyDNRequest       Application = 12
	ApplicationModifyDNResponse      Application = 13
	ApplicationCompareRequest        Application = 14
	ApplicationCompareResponse       Application = 15
	ApplicationAbandonRequest        Application = 16
	ApplicationSearchResultReference Application = 19
	ApplicationExtendedRequest       Application = 23
	ApplicationExtendedResponse      Application = 24
)

// DebugBinaryFile reads and prints packets from the given filename
func DebugBinaryFile(fileName string) error {
	file, err := ioutil.ReadFile(fileName)
	if err != nil {
		return NewError(ErrorDebugging, err)
	}
	fmt.Fprintf(os.Stdout, "---\n%s\n---", hex.Dump(file))
	packet, err := ber.ParseBytes(file)
	if err != nil {
		return fmt.Errorf("failed to decode packet: %s", err)
	}
	if err := AddLDAPDescriptions(packet); err != nil {
		return err
	}
	packet.PrettyPrint(os.Stdout, 0)
	return nil
}

// CompareRequest represents an LDAP CompareRequest operation.
type CompareRequest struct {
	DN        string
	Attribute string
	Value     string
}

func (req *CompareRequest) AppendTo(envelope *ber.Packet) error {
	pkt := ber.NewPacket(ber.ClassApplication, ber.TypeConstructed, ApplicationCompareRequest.Tag(), nil, "Compare Request")
	pkt.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, req.DN, "DN"))
	ava := ber.NewPacket(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "AttributeValueAssertion")
	ava.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, req.Attribute, "AttributeDesc"))
	ava.AppendChild(ber.NewPacket(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, req.Value, "AssertionValue"))
	pkt.AppendChild(ava)
	envelope.AppendChild(pkt)
	return nil
}

// DeleteRequest implements an LDAP deletion request
type DeleteRequest struct {
	// DN is the name of the directory entry to delete
	DN string
	// Controls hold optional controls to send with the request
	Controls []control.Control
}

func (req *DeleteRequest) AppendTo(envelope *ber.Packet) error {
	pkt := ber.NewPacket(ber.ClassApplication, ber.TypePrimitive, ApplicationDeleteRequest.Tag(), req.DN, "Del Request")
	pkt.Data.Write([]byte(req.DN))
	envelope.AppendChild(pkt)
	if len(req.Controls) > 0 {
		envelope.AppendChild(control.Encode(req.Controls...))
	}
	return nil
}

// NewDeleteRequest creates a delete request for the given DN and controls
func NewDeleteRequest(dn string, controls ...control.Control) *DeleteRequest {
	return &DeleteRequest{
		DN:       dn,
		Controls: controls,
	}
}

// ModifyDNRequest holds the request to modify a DN
type ModifyDNRequest struct {
	DN           string
	NewRDN       string
	DeleteOldRDN bool
	NewSuperior  string
}

// NewModifyDNRequest creates a new request which can be passed to ModifyDN().
//
// To move an object in the tree, set the "newSup" to the new parent entry DN. Use an
// empty string for just changing the object's RDN.
//
// For moving the object without renaming, the "rdn" must be the first
// RDN of the given DN.
//
// A call like
//   mdnReq := NewModifyDNRequest("uid=someone,dc=example,dc=org", "uid=newname", true, "")
// will setup the request to just rename uid=someone,dc=example,dc=org to
// uid=newname,dc=example,dc=org.
func NewModifyDNRequest(dn string, rdn string, delOld bool, newSup string) *ModifyDNRequest {
	return &ModifyDNRequest{
		DN:           dn,
		NewRDN:       rdn,
		DeleteOldRDN: delOld,
		NewSuperior:  newSup,
	}
}

func (req *ModifyDNRequest) AppendTo(envelope *ber.Packet) error {
	pkt := ber.NewPacket(ber.ClassApplication, ber.TypeConstructed, ApplicationModifyDNRequest.Tag(), nil, "Modify DN Request")
	pkt.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, req.DN, "DN"))
	pkt.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, req.NewRDN, "New RDN"))
	if req.DeleteOldRDN {
		buf := []byte{0xff}
		pkt.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagBoolean, string(buf), "Delete old RDN"))
	} else {
		pkt.AppendChild(ber.NewBoolean(ber.ClassUniversal, ber.TypePrimitive, ber.TagBoolean, req.DeleteOldRDN, "Delete old RDN"))
	}
	if req.NewSuperior != "" {
		pkt.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, 0, req.NewSuperior, "New Superior"))
	}
	envelope.AppendChild(pkt)
	return nil
}

// AddRequest represents an LDAP AddRequest operation
type AddRequest struct {
	// DN identifies the entry being added
	DN string
	// Attributes list the attributes of the new entry
	Attributes []Attribute
	// Controls hold optional controls to send with the request
	Controls []control.Control
}

func (req *AddRequest) AppendTo(envelope *ber.Packet) error {
	pkt := ber.NewPacket(ber.ClassApplication, ber.TypeConstructed, ApplicationAddRequest.Tag(), nil, "Add Request")
	pkt.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, req.DN, "DN"))
	attributes := ber.NewPacket(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Attributes")
	for _, attribute := range req.Attributes {
		attributes.AppendChild(attribute.encode())
	}
	pkt.AppendChild(attributes)
	envelope.AppendChild(pkt)
	if len(req.Controls) > 0 {
		envelope.AppendChild(control.Encode(req.Controls...))
	}
	return nil
}

// Attribute adds an attribute with the given type and values
func (req *AddRequest) Attribute(attrType string, attrVals []string) {
	req.Attributes = append(req.Attributes, Attribute{Type: attrType, Vals: attrVals})
}

// NewAddRequest returns an AddRequest for the given DN, with no attributes
func NewAddRequest(dn string, controls ...control.Control) *AddRequest {
	return &AddRequest{
		DN:       dn,
		Controls: controls,
	}
}

// SimpleBindRequest represents a username/password bind operation
type SimpleBindRequest struct {
	// Username is the name of the Directory object that the client wishes to bind as
	Username string
	// Password is the credentials to bind with
	Password string
	// Controls are optional controls to send with the bind request
	Controls []control.Control
	// AllowEmptyPassword sets whether the client allows binding with an empty password
	// (normally used for unauthenticated bind).
	AllowEmptyPassword bool
}

// SimpleBindResult contains the response from the server
type SimpleBindResult struct {
	Controls []control.Control
}

// NewSimpleBindRequest returns a bind request
func NewSimpleBindRequest(username string, password string, controls ...control.Control) *SimpleBindRequest {
	return &SimpleBindRequest{
		Username:           username,
		Password:           password,
		Controls:           controls,
		AllowEmptyPassword: false,
	}
}

func (req *SimpleBindRequest) AppendTo(envelope *ber.Packet) error {
	pkt := ber.NewPacket(ber.ClassApplication, ber.TypeConstructed, ApplicationBindRequest.Tag(), nil, "Bind Request")
	pkt.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 3, "Version"))
	pkt.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, req.Username, "User Name"))
	pkt.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, 0, req.Password, "Password"))
	envelope.AppendChild(pkt)
	if len(req.Controls) > 0 {
		envelope.AppendChild(control.Encode(req.Controls...))
	}
	return nil
}

// DigestMD5BindRequest represents a digest-md5 bind operation
type DigestMD5BindRequest struct {
	Host string
	// Username is the name of the Directory object that the client wishes to bind as
	Username string
	// Password is the credentials to bind with
	Password string
	// Controls are optional controls to send with the bind request
	Controls []control.Control
}

func (req *DigestMD5BindRequest) AppendTo(envelope *ber.Packet) error {
	request := ber.NewPacket(ber.ClassApplication, ber.TypeConstructed, ApplicationBindRequest.Tag(), nil, "Bind Request")
	request.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 3, "Version"))
	request.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "User Name"))
	auth := ber.NewPacket(ber.ClassContext, ber.TypeConstructed, 3, "", "authentication")
	auth.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "DIGEST-MD5", "SASL Mech"))
	request.AppendChild(auth)
	envelope.AppendChild(request)
	if len(req.Controls) > 0 {
		envelope.AppendChild(control.Encode(req.Controls...))
	}
	return nil
}

// DigestMD5BindResult contains the response from the server
type DigestMD5BindResult struct {
	Controls []control.Control
}

func parseParams(str string) (map[string]string, error) {
	m := make(map[string]string)
	var key, value string
	var state int
	for i := 0; i <= len(str); i++ {
		switch state {
		case 0: // reading key
			if i == len(str) {
				return nil, fmt.Errorf("syntax error on %d", i)
			}
			if str[i] != '=' {
				key += string(str[i])
				continue
			}
			state = 1
		case 1: // reading value
			if i == len(str) {
				m[key] = value
				break
			}
			switch str[i] {
			case ',':
				m[key] = value
				state = 0
				key = ""
				value = ""
			case '"':
				if value != "" {
					return nil, fmt.Errorf("syntax error on %d", i)
				}
				state = 2
			default:
				value += string(str[i])
			}
		case 2: // inside quotes
			if i == len(str) {
				return nil, fmt.Errorf("syntax error on %d", i)
			}
			if str[i] != '"' {
				value += string(str[i])
			} else {
				state = 1
			}
		}
	}
	return m, nil
}

func computeResponse(params map[string]string, uri, username, password string) string {
	nc := "00000001"
	qop := "auth"
	cnonce := hex.EncodeToString(randomBytes(16))
	x := username + ":" + params["realm"] + ":" + password
	y := md5Hash([]byte(x))
	a1 := bytes.NewBuffer(y)
	a1.WriteString(":" + params["nonce"] + ":" + cnonce)
	if len(params["authzid"]) > 0 {
		a1.WriteString(":" + params["authzid"])
	}
	a2 := bytes.NewBuffer([]byte("AUTHENTICATE"))
	a2.WriteString(":" + uri)
	ha1 := hex.EncodeToString(md5Hash(a1.Bytes()))
	ha2 := hex.EncodeToString(md5Hash(a2.Bytes()))
	kd := ha1
	kd += ":" + params["nonce"]
	kd += ":" + nc
	kd += ":" + cnonce
	kd += ":" + qop
	kd += ":" + ha2
	resp := hex.EncodeToString(md5Hash([]byte(kd)))
	return fmt.Sprintf(
		`username="%s",realm="%s",nonce="%s",cnonce="%s",nc=00000001,qop=%s,digest-uri="%s",response=%s`,
		username,
		params["realm"],
		params["nonce"],
		cnonce,
		qop,
		uri,
		resp,
	)
}

func md5Hash(b []byte) []byte {
	hasher := md5.New()
	hasher.Write(b)
	return hasher.Sum(nil)
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	for i := 0; i < n; i++ {
		b[i] = byte(rand.Intn(256))
	}
	return b
}

var externalBindRequest = RequestFunc(func(envelope *ber.Packet) error {
	pkt := ber.NewPacket(ber.ClassApplication, ber.TypeConstructed, ApplicationBindRequest.Tag(), nil, "Bind Request")
	pkt.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 3, "Version"))
	pkt.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "User Name"))
	saslAuth := ber.NewPacket(ber.ClassContext, ber.TypeConstructed, 3, "", "authentication")
	saslAuth.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "EXTERNAL", "SASL Mech"))
	saslAuth.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "SASL Cred"))
	pkt.AppendChild(saslAuth)
	envelope.AppendChild(pkt)
	return nil
})

// NTLMBind performs an NTLMSSP bind leveraging https://github.com/Azure/go-ntlmssp
// NTLMBindRequest represents an NTLMSSP bind operation
type NTLMBindRequest struct {
	// Domain is the AD Domain to authenticate too. If not specified, it will be grabbed from the NTLMSSP Challenge
	Domain string
	// Username is the name of the Directory object that the client wishes to bind as
	Username string
	// Password is the credentials to bind with
	Password string
	// Hash is the hex NTLM hash to bind with. Password or hash must be provided
	Hash string
	// Controls are optional controls to send with the bind request
	Controls []control.Control
}

func (req *NTLMBindRequest) AppendTo(envelope *ber.Packet) error {
	request := ber.NewPacket(ber.ClassApplication, ber.TypeConstructed, ApplicationBindRequest.Tag(), nil, "Bind Request")
	request.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 3, "Version"))
	request.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "User Name"))
	// generate an NTLMSSP Negotiation message for the  specified domain (it can be blank)
	negMessage, err := ntlmssp.NewNegotiateMessage(req.Domain, "")
	if err != nil {
		return fmt.Errorf("err creating negmessage: %s", err)
	}
	// append the generated NTLMSSP message as a TagEnumerated BER value
	auth := ber.NewPacket(ber.ClassContext, ber.TypePrimitive, ber.TagEnumerated, negMessage, "authentication")
	request.AppendChild(auth)
	envelope.AppendChild(request)
	if len(req.Controls) > 0 {
		envelope.AppendChild(control.Encode(req.Controls...))
	}
	return nil
}

// NTLMBindResult contains the response from the server
type NTLMBindResult struct {
	Controls []control.Control
}

// ModifyRequest as defined in https://tools.ietf.org/html/rfc4511
type ModifyRequest struct {
	// DN is the distinguishedName of the directory entry to modify
	DN string
	// Changes contain the attributes to modify
	Changes []Change
	// Controls hold optional controls to send with the request
	Controls []control.Control
}

// Add appends the given attribute to the list of changes to be made
func (req *ModifyRequest) Add(attrType string, attrVals []string) {
	req.appendChange(AddAttribute, attrType, attrVals)
}

// Delete appends the given attribute to the list of changes to be made
func (req *ModifyRequest) Delete(attrType string, attrVals []string) {
	req.appendChange(DeleteAttribute, attrType, attrVals)
}

// Replace appends the given attribute to the list of changes to be made
func (req *ModifyRequest) Replace(attrType string, attrVals []string) {
	req.appendChange(ReplaceAttribute, attrType, attrVals)
}

// Increment appends the given attribute to the list of changes to be made
func (req *ModifyRequest) Increment(attrType string, attrVal string) {
	req.appendChange(IncrementAttribute, attrType, []string{attrVal})
}

func (req *ModifyRequest) appendChange(operation uint, attrType string, attrVals []string) {
	req.Changes = append(req.Changes, Change{operation, PartialAttribute{Type: attrType, Vals: attrVals}})
}

func (req *ModifyRequest) AppendTo(envelope *ber.Packet) error {
	pkt := ber.NewPacket(ber.ClassApplication, ber.TypeConstructed, ApplicationModifyRequest.Tag(), nil, "Modify Request")
	pkt.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, req.DN, "DN"))
	changes := ber.NewPacket(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Changes")
	for _, change := range req.Changes {
		changes.AppendChild(change.encode())
	}
	pkt.AppendChild(changes)
	envelope.AppendChild(pkt)
	if len(req.Controls) > 0 {
		envelope.AppendChild(control.Encode(req.Controls...))
	}
	return nil
}

// NewModifyRequest creates a modify request for the given DN
func NewModifyRequest(dn string, controls ...control.Control) *ModifyRequest {
	return &ModifyRequest{
		DN:       dn,
		Controls: controls,
	}
}

const (
	passwordModifyOID = "1.3.6.1.4.1.4203.1.11.1"
)

// PasswordModifyRequest implements the Password Modify Extended Operation as defined in https://www.ietf.org/rfc/rfc3062.txt
type PasswordModifyRequest struct {
	// UserIdentity is an optional string representation of the user associated with the request.
	// This string may or may not be an LDAPDN [RFC2253].
	// If no UserIdentity field is present, the request acts up upon the password of the user currently associated with the LDAP session
	UserIdentity string
	// OldPassword, if present, contains the user's current password
	OldPassword string
	// NewPassword, if present, contains the desired password for this user
	NewPassword string
}

// PasswordModifyResult holds the server response to a PasswordModifyRequest
type PasswordModifyResult struct {
	// GeneratedPassword holds a password generated by the server, if present
	GeneratedPassword string
	// Referral are the returned referral
	Referral string
}

func (req *PasswordModifyRequest) AppendTo(envelope *ber.Packet) error {
	pkt := ber.NewPacket(ber.ClassApplication, ber.TypeConstructed, ApplicationExtendedRequest.Tag(), nil, "Password Modify Extended Operation")
	pkt.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, 0, passwordModifyOID, "Extended Request Name: Password Modify OID"))
	extendedRequestValue := ber.NewPacket(ber.ClassContext, ber.TypePrimitive, 1, nil, "Extended Request Value: Password Modify Request")
	passwordModifyRequestValue := ber.NewPacket(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Password Modify Request")
	if req.UserIdentity != "" {
		passwordModifyRequestValue.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, 0, req.UserIdentity, "User Identity"))
	}
	if req.OldPassword != "" {
		passwordModifyRequestValue.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, 1, req.OldPassword, "Old Password"))
	}
	if req.NewPassword != "" {
		passwordModifyRequestValue.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, 2, req.NewPassword, "New Password"))
	}
	extendedRequestValue.AppendChild(passwordModifyRequestValue)
	pkt.AppendChild(extendedRequestValue)
	envelope.AppendChild(pkt)
	return nil
}

// NewPasswordModifyRequest creates a new PasswordModifyRequest
//
// According to the RFC 3602 (https://tools.ietf.org/html/rfc3062):
// userIdentity is a string representing the user associated with the request.
// This string may or may not be an LDAPDN (RFC 2253).
// If userIdentity is empty then the operation will act on the user associated
// with the session.
//
// oldPassword is the current user's password, it can be empty or it can be
// needed depending on the session user access rights (usually an administrator
// can change a user's password without knowing the current one) and the
// password policy (see pwdSafeModify password policy's attribute)
//
// newPassword is the desired user's password. If empty the server can return
// an error or generate a new password that will be available in the
// PasswordModifyResult.GeneratedPassword
//
func NewPasswordModifyRequest(userIdentity string, oldPassword string, newPassword string) *PasswordModifyRequest {
	return &PasswordModifyRequest{
		UserIdentity: userIdentity,
		OldPassword:  oldPassword,
		NewPassword:  newPassword,
	}
}

// scope choices
const (
	ScopeBaseObject   = 0
	ScopeSingleLevel  = 1
	ScopeWholeSubtree = 2
)

// ScopeMap contains human readable descriptions of scope choices
var ScopeMap = map[int]string{
	ScopeBaseObject:   "Base Object",
	ScopeSingleLevel:  "Single Level",
	ScopeWholeSubtree: "Whole Subtree",
}

// derefAliases
const (
	NeverDerefAliases   = 0
	DerefInSearching    = 1
	DerefFindingBaseObj = 2
	DerefAlways         = 3
)

// DerefMap contains human readable descriptions of derefAliases choices
var DerefMap = map[int]string{
	NeverDerefAliases:   "NeverDerefAliases",
	DerefInSearching:    "DerefInSearching",
	DerefFindingBaseObj: "DerefFindingBaseObj",
	DerefAlways:         "DerefAlways",
}

// NewEntry returns an Entry object with the specified distinguished name and attribute key-value pairs.
// The map of attributes is accessed in alphabetical order of the keys in order to ensure that, for the
// same input map of attributes, the output entry will contain the same order of attributes
func NewEntry(dn string, attributes map[string][]string) *Entry {
	var attributeNames []string
	for attributeName := range attributes {
		attributeNames = append(attributeNames, attributeName)
	}
	sort.Strings(attributeNames)
	var encodedAttributes []*EntryAttribute
	for _, attributeName := range attributeNames {
		encodedAttributes = append(encodedAttributes, NewEntryAttribute(attributeName, attributes[attributeName]))
	}
	return &Entry{
		DN:         dn,
		Attributes: encodedAttributes,
	}
}

// Entry represents a single search result entry
type Entry struct {
	// DN is the distinguished name of the entry
	DN string
	// Attributes are the returned attributes for the entry
	Attributes []*EntryAttribute
}

// GetAttributeValues returns the values for the named attribute, or an empty list
func (e *Entry) GetAttributeValues(attribute string) []string {
	for _, attr := range e.Attributes {
		if attr.Name == attribute {
			return attr.Values
		}
	}
	return []string{}
}

// GetEqualFoldAttributeValues returns the values for the named attribute, or an
// empty list. Attribute matching is done with strings.EqualFold.
func (e *Entry) GetEqualFoldAttributeValues(attribute string) []string {
	for _, attr := range e.Attributes {
		if strings.EqualFold(attribute, attr.Name) {
			return attr.Values
		}
	}
	return []string{}
}

// GetRawAttributeValues returns the byte values for the named attribute, or an empty list
func (e *Entry) GetRawAttributeValues(attribute string) [][]byte {
	for _, attr := range e.Attributes {
		if attr.Name == attribute {
			return attr.ByteValues
		}
	}
	return [][]byte{}
}

// GetEqualFoldRawAttributeValues returns the byte values for the named attribute, or an empty list
func (e *Entry) GetEqualFoldRawAttributeValues(attribute string) [][]byte {
	for _, attr := range e.Attributes {
		if strings.EqualFold(attr.Name, attribute) {
			return attr.ByteValues
		}
	}
	return [][]byte{}
}

// GetAttributeValue returns the first value for the named attribute, or ""
func (e *Entry) GetAttributeValue(attribute string) string {
	values := e.GetAttributeValues(attribute)
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

// GetEqualFoldAttributeValue returns the first value for the named attribute, or "".
// Attribute comparison is done with strings.EqualFold.
func (e *Entry) GetEqualFoldAttributeValue(attribute string) string {
	values := e.GetEqualFoldAttributeValues(attribute)
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

// GetRawAttributeValue returns the first value for the named attribute, or an empty slice
func (e *Entry) GetRawAttributeValue(attribute string) []byte {
	values := e.GetRawAttributeValues(attribute)
	if len(values) == 0 {
		return []byte{}
	}
	return values[0]
}

// GetEqualFoldRawAttributeValue returns the first value for the named attribute, or an empty slice
func (e *Entry) GetEqualFoldRawAttributeValue(attribute string) []byte {
	values := e.GetEqualFoldRawAttributeValues(attribute)
	if len(values) == 0 {
		return []byte{}
	}
	return values[0]
}

// Print outputs a human-readable description
func (e *Entry) Print() {
	fmt.Printf("DN: %s\n", e.DN)
	for _, attr := range e.Attributes {
		attr.Print()
	}
}

// PrettyPrint outputs a human-readable description indenting
func (e *Entry) PrettyPrint(indent int) {
	fmt.Printf("%sDN: %s\n", strings.Repeat(" ", indent), e.DN)
	for _, attr := range e.Attributes {
		attr.PrettyPrint(indent + 2)
	}
}

// NewEntryAttribute returns a new EntryAttribute with the desired key-value pair
func NewEntryAttribute(name string, values []string) *EntryAttribute {
	var bytes [][]byte
	for _, value := range values {
		bytes = append(bytes, []byte(value))
	}
	return &EntryAttribute{
		Name:       name,
		Values:     values,
		ByteValues: bytes,
	}
}

// EntryAttribute holds a single attribute
type EntryAttribute struct {
	// Name is the name of the attribute
	Name string
	// Values contain the string values of the attribute
	Values []string
	// ByteValues contain the raw values of the attribute
	ByteValues [][]byte
}

// Print outputs a human-readable description
func (e *EntryAttribute) Print() {
	fmt.Printf("%s: %s\n", e.Name, e.Values)
}

// PrettyPrint outputs a human-readable description with indenting
func (e *EntryAttribute) PrettyPrint(indent int) {
	fmt.Printf("%s%s: %s\n", strings.Repeat(" ", indent), e.Name, e.Values)
}

// SearchResult holds the server's response to a search request
type SearchResult struct {
	// Entries are the returned entries
	Entries []*Entry
	// Referrals are the returned referrals
	Referrals []string
	// Controls are the returned controls
	Controls []control.Control
}

// Print outputs a human-readable description
func (s *SearchResult) Print() {
	for _, entry := range s.Entries {
		entry.Print()
	}
}

// PrettyPrint outputs a human-readable description with indenting
func (s *SearchResult) PrettyPrint(indent int) {
	for _, entry := range s.Entries {
		entry.PrettyPrint(indent)
	}
}

// SearchRequest represents a search request to send to the server
type SearchRequest struct {
	BaseDN       string
	Scope        int
	DerefAliases int
	SizeLimit    int
	TimeLimit    int
	TypesOnly    bool
	Filter       string
	Attributes   []string
	Controls     []control.Control
}

func (req *SearchRequest) AppendTo(envelope *ber.Packet) error {
	pkt := ber.NewPacket(ber.ClassApplication, ber.TypeConstructed, ApplicationSearchRequest.Tag(), nil, "Search Request")
	pkt.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, req.BaseDN, "Base DN"))
	pkt.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, uint64(req.Scope), "Scope"))
	pkt.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, uint64(req.DerefAliases), "Deref Aliases"))
	pkt.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, uint64(req.SizeLimit), "Size Limit"))
	pkt.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, uint64(req.TimeLimit), "Time Limit"))
	pkt.AppendChild(ber.NewBoolean(ber.ClassUniversal, ber.TypePrimitive, ber.TagBoolean, req.TypesOnly, "Types Only"))
	// compile and encode filter
	filterPacket, err := filter.Compile(req.Filter)
	if err != nil {
		return err
	}
	pkt.AppendChild(filterPacket)
	// encode attributes
	attributesPacket := ber.NewPacket(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Attributes")
	for _, attribute := range req.Attributes {
		attributesPacket.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, attribute, "Attribute"))
	}
	pkt.AppendChild(attributesPacket)
	envelope.AppendChild(pkt)
	if len(req.Controls) > 0 {
		envelope.AppendChild(control.Encode(req.Controls...))
	}
	return nil
}

// NewSearchRequest creates a new search request
func NewSearchRequest(
	BaseDN string,
	Scope, DerefAliases, SizeLimit, TimeLimit int,
	TypesOnly bool,
	Filter string,
	Attributes []string,
	Controls ...control.Control,
) *SearchRequest {
	return &SearchRequest{
		BaseDN:       BaseDN,
		Scope:        Scope,
		DerefAliases: DerefAliases,
		SizeLimit:    SizeLimit,
		TimeLimit:    TimeLimit,
		TypesOnly:    TypesOnly,
		Filter:       Filter,
		Attributes:   Attributes,
		Controls:     Controls,
	}
}
