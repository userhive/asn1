// Code generated by "stringer -type DerefAliases -trimprefix DerefAliases"; DO NOT EDIT.

package ldap

import "strconv"

func _() {
	// An "invalid array index" compiler error signifies that the constant values have changed.
	// Re-run the stringer command to generate them again.
	var x [1]struct{}
	_ = x[DerefAliasesNever-0]
	_ = x[DerefAliasesInSearching-1]
	_ = x[DerefAliasesFindingBaseObject-2]
	_ = x[DerefAliasesAlways-3]
}

const _DerefAliases_name = "NeverInSearchingFindingBaseObjectAlways"

var _DerefAliases_index = [...]uint8{0, 5, 16, 33, 39}

func (i DerefAliases) String() string {
	if i < 0 || i >= DerefAliases(len(_DerefAliases_index)-1) {
		return "DerefAliases(" + strconv.FormatInt(int64(i), 10) + ")"
	}
	return _DerefAliases_name[_DerefAliases_index[i]:_DerefAliases_index[i+1]]
}
