package ldaputil

//go:generate stringer -type Application -trimprefix Application
//go:generate stringer -type Result -trimprefix Result

import (
	"github.com/userhive/asn1/ber"
)

// Application is the ldap application enum.
type Application ber.Tag

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

// Tag returns the application as a ber.Tag.
func (app Application) Tag() ber.Tag {
	return ber.Tag(app)
}

// Response returns the corresponding response for the app.
func (app Application) Response() Application {
	if app == ApplicationSearchRequest {
		return ApplicationSearchResultDone
	}
	return app + 1
}

// Result is a ldap result code.
type Result uint16

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
	ResultNotAllowedOnNonLeaf                Result = 66   // Results Too Large
	ResultNotAllowedOnRDN                    Result = 67   // Not Allowed On Non Leaf
	ResultEntryAlreadyExists                 Result = 68   // Not Allowed On RDN
	ResultObjectClassModsProhibited          Result = 69   // Entry Already Exists
	ResultResultsTooLarge                    Result = 70   // Object Class Mods Prohibited
	ResultAffectsMultipleDSAs                Result = 71   // Affects Multiple DSAs
	ResultVirtualListViewErrorOrControlError Result = 76   // Failed because of a problem related to the virtual list view
	ResultOtherError                         Result = 80   // Other error
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
	ResultInvalidResponse                    Result = 100  // Invalid Response
	ResultAmbiguousResponse                  Result = 101  // Ambiguous Response
	ResultTLSNotSupported                    Result = 112  // Tls Not Supported
	ResultIntermediateResponse               Result = 113  // The identified operation does not support cancellation or the cancel operation cannot be performed
	ResultUnknownType                        Result = 114  // Unknown Type
	ResultCanceled                           Result = 118  // Operation was canceled
	ResultNoSuchOperation                    Result = 119  // Server has no knowledge of the operation requested for cancellation
	ResultTooLate                            Result = 120  // Too late to cancel the outstanding operation
	ResultCannotCancel                       Result = 121  // Cannot cancel
	ResultAssertionFailed                    Result = 122  // An assertion control given in the LDAP operation evaluated to false causing the operation to not be performed
	ResultAuthorizationDenied                Result = 123  // Authorization Denied
	ResultSyncRefreshRequired                Result = 4096 // Refresh Required
	ResultClientError                        Result = 200  // Client network error
)
