package minion

import "testing"

func TestHasAnyRole(t *testing.T) {
	var principal Principal
	if principal.HasAnyRole() {
		t.Errorf("nil principal shouldn't have empty role")
	}
	if principal.HasAnyRole("*") {
		t.Errorf("nil principal should not have role '*'")
	}

	if principal.HasAnyRole("user", "admin") {
		t.Errorf("nil principal should not have role 'user' or 'admin'")
	}

	principal = Principal{Login: "foo", Authenticated: true, Roles: "user admin"}
	if principal.HasAnyRole() {
		t.Errorf("foo principal shouldn't have empty role")
	}
	if !principal.HasAnyRole("*") {
		t.Errorf("foo principal should have role '*'")
	}
	if !principal.HasAnyRole("user", "admin") {
		t.Errorf("foo principal should have role 'user' or 'admin'")
	}
	if principal.HasAnyRole("dummy") {
		t.Errorf("foo principal shouldn't have role 'dummy'")
	}
}
