package control

// Behera is the behera password policy enum.
//
// see: Behera Password Policy Draft 10 (https://tools.ietf.org/html/draft-behera-ldap-password-policy-10)
type Behera int

// Behera values.
const (
	BeheraPasswordExpired             Behera = 0
	BeheraAccountLocked               Behera = 1
	BeheraChangeAfterReset            Behera = 2
	BeheraPasswordModNotAllowed       Behera = 3
	BeheraMustSupplyOldPassword       Behera = 4
	BeheraInsufficientPasswordQuality Behera = 5
	BeheraPasswordTooShort            Behera = 6
	BeheraPasswordTooYoung            Behera = 7
	BeheraPasswordInHistory           Behera = 8
)

// BeheraPasswordPolicyErrorMap contains human readable descriptions of Behera
// Password Policy error codes
var BeheraPasswordPolicyErrorMap = map[Behera]string{
	BeheraPasswordExpired:             "Password expired",
	BeheraAccountLocked:               "Account locked",
	BeheraChangeAfterReset:            "Password must be changed",
	BeheraPasswordModNotAllowed:       "Policy prevents password modification",
	BeheraMustSupplyOldPassword:       "Policy requires old password in order to change password",
	BeheraInsufficientPasswordQuality: "Password fails quality checks",
	BeheraPasswordTooShort:            "Password is too short for policy",
	BeheraPasswordTooYoung:            "Password has been changed too recently",
	BeheraPasswordInHistory:           "New password is in list of old passwords",
}
