// Code generated by "stringer -type Class -trimprefix Class ."; DO NOT EDIT.

package ber

import "strconv"

func _() {
	// An "invalid array index" compiler error signifies that the constant values have changed.
	// Re-run the stringer command to generate them again.
	var x [1]struct{}
	_ = x[ClassUniversal-0]
	_ = x[ClassApplication-64]
	_ = x[ClassContext-128]
	_ = x[ClassPrivate-192]
}

const (
	_Class_name_0 = "Universal"
	_Class_name_1 = "Application"
	_Class_name_2 = "Context"
	_Class_name_3 = "Private"
)

func (i Class) String() string {
	switch {
	case i == 0:
		return _Class_name_0
	case i == 64:
		return _Class_name_1
	case i == 128:
		return _Class_name_2
	case i == 192:
		return _Class_name_3
	default:
		return "Class(" + strconv.FormatInt(int64(i), 10) + ")"
	}
}
