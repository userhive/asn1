package ldapclient

import (
	"fmt"

	"github.com/userhive/asn1/ber"
)

// LDAP Result Codes
const (
	ResultSuccess                            = 0
	ResultOperationsError                    = 1
	ResultProtocolError                      = 2
	ResultTimeLimitExceeded                  = 3
	ResultSizeLimitExceeded                  = 4
	ResultCompareFalse                       = 5
	ResultCompareTrue                        = 6
	ResultAuthMethodNotSupported             = 7
	ResultStrongAuthRequired                 = 8
	ResultReferral                           = 10
	ResultAdminLimitExceeded                 = 11
	ResultUnavailableCriticalExtension       = 12
	ResultConfidentialityRequired            = 13
	ResultSaslBindInProgress                 = 14
	ResultNoSuchAttribute                    = 16
	ResultUndefinedAttributeType             = 17
	ResultInappropriateMatching              = 18
	ResultConstraintViolation                = 19
	ResultAttributeOrValueExists             = 20
	ResultInvalidAttributeSyntax             = 21
	ResultNoSuchObject                       = 32
	ResultAliasProblem                       = 33
	ResultInvalidDNSyntax                    = 34
	ResultIsLeaf                             = 35
	ResultAliasDereferencingProblem          = 36
	ResultInappropriateAuthentication        = 48
	ResultInvalidCredentials                 = 49
	ResultInsufficientAccessRights           = 50
	ResultBusy                               = 51
	ResultUnavailable                        = 52
	ResultUnwillingToPerform                 = 53
	ResultLoopDetect                         = 54
	ResultSortControlMissing                 = 60
	ResultOffsetRangeError                   = 61
	ResultNamingViolation                    = 64
	ResultObjectClassViolation               = 65
	ResultNotAllowedOnNonLeaf                = 66
	ResultNotAllowedOnRDN                    = 67
	ResultEntryAlreadyExists                 = 68
	ResultObjectClassModsProhibited          = 69
	ResultResultsTooLarge                    = 70
	ResultAffectsMultipleDSAs                = 71
	ResultVirtualListViewErrorOrControlError = 76
	ResultOther                              = 80
	ResultServerDown                         = 81
	ResultLocalError                         = 82
	ResultEncodingError                      = 83
	ResultDecodingError                      = 84
	ResultTimeout                            = 85
	ResultAuthUnknown                        = 86
	ResultFilterError                        = 87
	ResultUserCanceled                       = 88
	ResultParamError                         = 89
	ResultNoMemory                           = 90
	ResultConnectError                       = 91
	ResultNotSupported                       = 92
	ResultControlNotFound                    = 93
	ResultNoResultsReturned                  = 94
	ResultMoreResultsToReturn                = 95
	ResultClientLoop                         = 96
	ResultReferralLimitExceeded              = 97
	ResultInvalidResponse                    = 100
	ResultAmbiguousResponse                  = 101
	ResultTLSNotSupported                    = 112
	ResultIntermediateResponse               = 113
	ResultUnknownType                        = 114
	ResultCanceled                           = 118
	ResultNoSuchOperation                    = 119
	ResultTooLate                            = 120
	ResultCannotCancel                       = 121
	ResultAssertionFailed                    = 122
	ResultAuthorizationDenied                = 123
	ResultSyncRefreshRequired                = 4096
	ErrorNetwork                             = 200
	ErrorFilterCompile                       = 201
	ErrorFilterDecompile                     = 202
	ErrorDebugging                           = 203
	ErrorUnexpectedMessage                   = 204
	ErrorUnexpectedResponse                  = 205
	ErrorEmptyPassword                       = 206
)

// ResultCodeMap contains string descriptions for LDAP error codes
var ResultCodeMap = map[uint16]string{
	ResultSuccess:                            "Success",
	ResultOperationsError:                    "Operations Error",
	ResultProtocolError:                      "Protocol Error",
	ResultTimeLimitExceeded:                  "Time Limit Exceeded",
	ResultSizeLimitExceeded:                  "Size Limit Exceeded",
	ResultCompareFalse:                       "Compare False",
	ResultCompareTrue:                        "Compare True",
	ResultAuthMethodNotSupported:             "Auth Method Not Supported",
	ResultStrongAuthRequired:                 "Strong Auth Required",
	ResultReferral:                           "Referral",
	ResultAdminLimitExceeded:                 "Admin Limit Exceeded",
	ResultUnavailableCriticalExtension:       "Unavailable Critical Extension",
	ResultConfidentialityRequired:            "Confidentiality Required",
	ResultSaslBindInProgress:                 "Sasl Bind In Progress",
	ResultNoSuchAttribute:                    "No Such Attribute",
	ResultUndefinedAttributeType:             "Undefined Attribute Type",
	ResultInappropriateMatching:              "Inappropriate Matching",
	ResultConstraintViolation:                "Constraint Violation",
	ResultAttributeOrValueExists:             "Attribute Or Value Exists",
	ResultInvalidAttributeSyntax:             "Invalid Attribute Syntax",
	ResultNoSuchObject:                       "No Such Object",
	ResultAliasProblem:                       "Alias Problem",
	ResultInvalidDNSyntax:                    "Invalid DN Syntax",
	ResultIsLeaf:                             "Is Leaf",
	ResultAliasDereferencingProblem:          "Alias Dereferencing Problem",
	ResultInappropriateAuthentication:        "Inappropriate Authentication",
	ResultInvalidCredentials:                 "Invalid Credentials",
	ResultInsufficientAccessRights:           "Insufficient Access Rights",
	ResultBusy:                               "Busy",
	ResultUnavailable:                        "Unavailable",
	ResultUnwillingToPerform:                 "Unwilling To Perform",
	ResultLoopDetect:                         "Loop Detect",
	ResultSortControlMissing:                 "Sort Control Missing",
	ResultOffsetRangeError:                   "Result Offset Range Error",
	ResultNamingViolation:                    "Naming Violation",
	ResultObjectClassViolation:               "Object Class Violation",
	ResultResultsTooLarge:                    "Results Too Large",
	ResultNotAllowedOnNonLeaf:                "Not Allowed On Non Leaf",
	ResultNotAllowedOnRDN:                    "Not Allowed On RDN",
	ResultEntryAlreadyExists:                 "Entry Already Exists",
	ResultObjectClassModsProhibited:          "Object Class Mods Prohibited",
	ResultAffectsMultipleDSAs:                "Affects Multiple DSAs",
	ResultVirtualListViewErrorOrControlError: "Failed because of a problem related to the virtual list view",
	ResultOther:                              "Other",
	ResultServerDown:                         "Cannot establish a connection",
	ResultLocalError:                         "An error occurred",
	ResultEncodingError:                      "LDAP encountered an error while encoding",
	ResultDecodingError:                      "LDAP encountered an error while decoding",
	ResultTimeout:                            "LDAP timeout while waiting for a response from the server",
	ResultAuthUnknown:                        "The auth method requested in a bind request is unknown",
	ResultFilterError:                        "An error occurred while encoding the given search filter",
	ResultUserCanceled:                       "The user canceled the operation",
	ResultParamError:                         "An invalid parameter was specified",
	ResultNoMemory:                           "Out of memory error",
	ResultConnectError:                       "A connection to the server could not be established",
	ResultNotSupported:                       "An attempt has been made to use a feature not supported LDAP",
	ResultControlNotFound:                    "The controls required to perform the requested operation were not found",
	ResultNoResultsReturned:                  "No results were returned from the server",
	ResultMoreResultsToReturn:                "There are more results in the chain of results",
	ResultClientLoop:                         "A loop has been detected. For example when following referrals",
	ResultReferralLimitExceeded:              "The referral hop limit has been exceeded",
	ResultCanceled:                           "Operation was canceled",
	ResultNoSuchOperation:                    "Server has no knowledge of the operation requested for cancellation",
	ResultTooLate:                            "Too late to cancel the outstanding operation",
	ResultCannotCancel:                       "The identified operation does not support cancellation or the cancel operation cannot be performed",
	ResultAssertionFailed:                    "An assertion control given in the LDAP operation evaluated to false causing the operation to not be performed",
	ResultSyncRefreshRequired:                "Refresh Required",
	ResultInvalidResponse:                    "Invalid Response",
	ResultAmbiguousResponse:                  "Ambiguous Response",
	ResultTLSNotSupported:                    "Tls Not Supported",
	ResultIntermediateResponse:               "Intermediate Response",
	ResultUnknownType:                        "Unknown Type",
	ResultAuthorizationDenied:                "Authorization Denied",
	ErrorNetwork:                             "Network Error",
	ErrorFilterCompile:                       "Filter Compile Error",
	ErrorFilterDecompile:                     "Filter Decompile Error",
	ErrorDebugging:                           "Debugging Error",
	ErrorUnexpectedMessage:                   "Unexpected Message",
	ErrorUnexpectedResponse:                  "Unexpected Response",
	ErrorEmptyPassword:                       "Empty password not allowed by the client",
}

// Error holds LDAP error information
type Error struct {
	// Err is the underlying error
	Err error
	// ResultCode is the LDAP error code
	ResultCode uint16
	// MatchedDN is the matchedDN returned if any
	MatchedDN string
	// Packet is the returned packet if any
	Packet *ber.Packet
}

func (e *Error) Error() string {
	return fmt.Sprintf("LDAP Result Code %d %q: %s", e.ResultCode, ResultCodeMap[e.ResultCode], e.Err.Error())
}

// GetLDAPError creates an Error out of a BER packet representing a Result
// The return is an error object. It can be casted to a Error structure.
// This function returns nil if resultCode in the Result sequence is success(0).
func GetLDAPError(p *ber.Packet) error {
	if p == nil {
		return &Error{ResultCode: ErrorUnexpectedResponse, Err: fmt.Errorf("Empty packet")}
	}
	if len(p.Children) >= 2 {
		response := p.Children[1]
		if response == nil {
			return &Error{ResultCode: ErrorUnexpectedResponse, Err: fmt.Errorf("Empty response in packet"), Packet: p}
		}
		if response.Class == ber.ClassApplication && response.Type == ber.TypeConstructed && len(response.Children) >= 3 {
			resultCode := uint16(response.Children[0].Value.(int64))
			if resultCode == 0 { // No error
				return nil
			}
			return &Error{
				ResultCode: resultCode,
				MatchedDN:  response.Children[1].Value.(string),
				Err:        fmt.Errorf("%s", response.Children[2].Value.(string)),
				Packet:     p,
			}
		}
	}
	return &Error{ResultCode: ErrorNetwork, Err: fmt.Errorf("Invalid packet format"), Packet: p}
}

// NewError creates an LDAP error with the given code and underlying error
func NewError(resultCode uint16, err error) error {
	return &Error{ResultCode: resultCode, Err: err}
}

// IsErrorAnyOf returns true if the given error is an LDAP error with any one of the given result codes
func IsErrorAnyOf(err error, codes ...uint16) bool {
	if err == nil {
		return false
	}
	serverError, ok := err.(*Error)
	if !ok {
		return false
	}
	for _, code := range codes {
		if serverError.ResultCode == code {
			return true
		}
	}
	return false
}

// IsErrorWithCode returns true if the given error is an LDAP error with the given result code
func IsErrorWithCode(err error, desiredResultCode uint16) bool {
	return IsErrorAnyOf(err, desiredResultCode)
}
