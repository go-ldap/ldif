package ldif_test

import (
	"errors"
	"testing"

	"github.com/go-ldap/ldap/v3"
	"github.com/go-ldap/ldif"
)

// recordingConn records the requests passed to it and satisfies ldap.Client
// via an embedded nil interface (only the methods Apply calls are implemented).
type recordingConn struct {
	ldap.Client
	adds    []*ldap.AddRequest
	dels    []*ldap.DelRequest
	mods    []*ldap.ModifyRequest
	failAdd bool
}

func (c *recordingConn) Add(r *ldap.AddRequest) error {
	c.adds = append(c.adds, r)
	if c.failAdd {
		return errors.New("boom")
	}
	return nil
}

func (c *recordingConn) Del(r *ldap.DelRequest) error {
	c.dels = append(c.dels, r)
	return nil
}

func (c *recordingConn) Modify(r *ldap.ModifyRequest) error {
	c.mods = append(c.mods, r)
	return nil
}

// A content entry must be applied as an Add without panicking.
func TestApplyContentEntry(t *testing.T) {
	l, err := ldif.Parse("dn: uid=someone,dc=example,dc=org\ncn: Someone\n")
	if err != nil {
		t.Fatalf("parse: %s", err)
	}
	conn := &recordingConn{}
	if err := l.Apply(conn, false); err != nil {
		t.Fatalf("apply: %s", err)
	}
	if len(conn.adds) != 1 {
		t.Fatalf("expected 1 add, got %d", len(conn.adds))
	}
	if conn.adds[0].DN != "uid=someone,dc=example,dc=org" {
		t.Errorf("wrong DN: %q", conn.adds[0].DN)
	}
	if got := conn.adds[0].Attributes[0].Vals[0]; got != "Someone" {
		t.Errorf("wrong cn: %q", got)
	}
}

// continueOnErr must skip failures instead of returning them.
func TestApplyContinueOnErr(t *testing.T) {
	l, err := ldif.Parse("dn: uid=a,dc=example,dc=org\ncn: A\n\ndn: uid=b,dc=example,dc=org\ncn: B\n")
	if err != nil {
		t.Fatalf("parse: %s", err)
	}
	conn := &recordingConn{failAdd: true}
	if err := l.Apply(conn, true); err != nil {
		t.Fatalf("apply with continueOnErr should not return: %s", err)
	}
	if len(conn.adds) != 2 {
		t.Errorf("expected both adds attempted, got %d", len(conn.adds))
	}

	conn = &recordingConn{failAdd: true}
	if err := l.Apply(conn, false); err == nil {
		t.Error("expected error without continueOnErr")
	}
	if len(conn.adds) != 1 {
		t.Errorf("expected to stop after first failure, got %d adds", len(conn.adds))
	}
}
