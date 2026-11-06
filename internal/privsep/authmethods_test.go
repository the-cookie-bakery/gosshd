package privsep

import (
	"reflect"
	"testing"
)

func TestInitialAuthMethods(t *testing.T) {
	alts := [][]string{
		{"publickey", "password"},
		{"publickey", "keyboard-interactive"},
		{"password"},
	}
	got := initialAuthMethods(alts)
	want := []string{"publickey", "password"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
	if got := initialAuthMethods(nil); len(got) != 0 {
		t.Fatalf("got %v, want empty", got)
	}
}

func TestAuthStep(t *testing.T) {
	alts := [][]string{
		{"publickey", "password"},
		{"publickey", "keyboard-interactive"},
	}
	final, next, done, ok := authStep(alts, nil, "publickey")
	if !ok || final {
		t.Fatalf("publickey: final=%v ok=%v", final, ok)
	}
	if !reflect.DeepEqual(next, []string{"password", "keyboard-interactive"}) {
		t.Fatalf("next=%v", next)
	}
	if !reflect.DeepEqual(done, []string{"publickey"}) {
		t.Fatalf("done=%v", done)
	}

	final, _, _, ok = authStep(alts, done, "password")
	if !ok || !final {
		t.Fatalf("password: final=%v ok=%v", final, ok)
	}

	if _, _, _, ok := authStep(alts, nil, "password"); ok {
		t.Fatal("password-first should be rejected")
	}
	if _, _, _, ok := authStep(alts, done, "publickey"); ok {
		t.Fatal("repeated publickey should be rejected")
	}
}

func TestAuthStepFullPrefix(t *testing.T) {
	alts := [][]string{
		{"publickey"},
		{"publickey", "password"},
	}
	final, _, _, ok := authStep(alts, nil, "publickey")
	if !ok || !final {
		t.Fatalf("expected completion via shortest alternative, final=%v ok=%v", final, ok)
	}
}

func TestAuthStepRepeatedMethod(t *testing.T) {
	alts := [][]string{{"publickey", "publickey"}}
	final, next, done, ok := authStep(alts, nil, "publickey")
	if !ok || final {
		t.Fatalf("first step: final=%v ok=%v", final, ok)
	}
	if !reflect.DeepEqual(next, []string{"publickey"}) {
		t.Fatalf("next=%v", next)
	}
	final, _, _, ok = authStep(alts, done, "publickey")
	if !ok || !final {
		t.Fatalf("second step: final=%v ok=%v", final, ok)
	}
}

func TestAuthStepWithoutConfiguration(t *testing.T) {
	final, next, done, ok := authStep(nil, nil, "password")
	if !ok || !final || next != nil {
		t.Fatalf("final=%v next=%v ok=%v", final, next, ok)
	}
	if !reflect.DeepEqual(done, []string{"password"}) {
		t.Fatalf("done=%v", done)
	}
}
