package asn1ber

// Error is a asn1 ber error.
type Error string

// Error satisfies the error interface.
func (err Error) Error() string {
	return string(err)
}

// Error values.
const (
	ErrBits6And5OfInformationOctetAreEqualTo11                 Error = "bits 6 and 5 of information octet are equal to 11"
	ErrEncodingOfSpecialValueMustNotContainExponentAndMantissa Error = "encoding of special value must not contain exponent and mantissa"
	ErrEOCChildNotAllowedWithDefiniteLength                    Error = "EOC child not allowed with definite length"
	ErrExponentTooLarge                                        Error = "exponent too large"
	ErrIndefiniteLengthUsedWithPrimitiveType                   Error = "indefinite length used with primitive type"
	ErrIntegerTooLarge                                         Error = "integer too large"
	ErrInvalidIA5String                                        Error = "invalid IA5 string"
	ErrInvalidInfoBlock                                        Error = "invalid info block"
	ErrInvalidNRForm                                           Error = "invalid NR form"
	ErrInvalidPrintableString                                  Error = "invalid Printable string"
	ErrInvalidSpecialValueEncoding                             Error = "invalid special value encoding"
	ErrInvalidTimeFormat                                       Error = "invalid time format"
	ErrInvalidUTF8String                                       Error = "invalid UTF-8 string"
	ErrLengthCannotBeLessThanNegative1                         Error = "length cannot be less than -1"
	ErrLengthGreaterThanMax                                    Error = "length greater than max"
	ErrMantissaTooLarge                                        Error = "mantissa too large"
	ErrNegative0MustBeEncodedAsASecialValue                    Error = "-0 must be encoded as a special value"
	ErrPastPacketBoundary                                      Error = "past packet boundary"
	ErrPlus0MustBeEncodedWithZeroLengthValueBlock              Error = "+0 must be encoded with zero-length value block"
	ErrUnexpectedEOF                                           Error = "unexpected EOF"
	ErrInvalidHighByte                                         Error = "invalid high byte"
	ErrTagValueOverflow                                        Error = "tag value overflow"
	ErrInvalidLength                                           Error = "invalid length"
	ErrLengthValueOverflow                                     Error = "length value overflow"
)
