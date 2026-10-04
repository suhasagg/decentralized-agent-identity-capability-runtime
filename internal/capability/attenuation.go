package capability

import "strings"

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

func resourceWithin(parent, child string) bool {
	if parent == child {
		return true
	}
	if strings.HasSuffix(parent, "/*") {
		return strings.HasPrefix(child, strings.TrimSuffix(parent, "*"))
	}
	return false
}

func IsAttenuation(parent, child Token) bool {
	if child.RootUserDID != parent.RootUserDID {
		return false
	}
	if child.IssuerDID != parent.SubjectDID {
		return false
	}
	if child.ParentID != parent.ID {
		return false
	}
	if child.Depth != parent.Depth+1 {
		return false
	}
	if child.Scope.ExpiresAt > parent.Scope.ExpiresAt {
		return false
	}
	if child.Scope.NotBefore < parent.Scope.NotBefore {
		return false
	}
	if parent.Scope.Audience != "*" && child.Scope.Audience != parent.Scope.Audience {
		return false
	}
	if !resourceWithin(parent.Scope.Resource, child.Scope.Resource) {
		return false
	}
	if parent.Scope.MaxCalls > 0 && (child.Scope.MaxCalls <= 0 || child.Scope.MaxCalls > parent.Scope.MaxCalls) {
		return false
	}
	for _, a := range child.Scope.Actions {
		if !contains(parent.Scope.Actions, a) {
			return false
		}
	}
	return true
}
