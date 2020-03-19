package ldif

import (
	"bytes"
	"github.com/go-ldap/ldap/v3"
	"testing"
)

var personLDIF = `dn: uid=someone,ou=people,dc=example,dc=org
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
uid: someone
cn: Someone
mail: someone@example.org

`

var ouLDIF = `dn: ou=people,dc=example,dc=org
objectClass: top
objectClass: organizationalUnit
ou: people

`

var entries = []*ldap.Entry{
	{
		DN: "ou=people,dc=example,dc=org",
		Attributes: []*ldap.EntryAttribute{
			{
				Name: "objectClass",
				Values: []string{
					"top",
					"organizationalUnit",
				},
			},
			{
				Name:   "ou",
				Values: []string{"people"},
			},
		},
	},
	{
		DN: "uid=someone,ou=people,dc=example,dc=org",
		Attributes: []*ldap.EntryAttribute{
			{
				Name: "objectClass",
				Values: []string{
					"top",
					"person",
					"organizationalPerson",
					"inetOrgPerson",
				},
			},
			{
				Name:   "uid",
				Values: []string{"someone"},
			},
			{
				Name:   "cn",
				Values: []string{"Someone"},
			},
			{
				Name:   "mail",
				Values: []string{"someone@example.org"},
			},
		},
	},
}

func TestMarshalSingleEntry(t *testing.T) {
	l := &LDIF{
		Entries: []*Entry{
			{Entry: entries[1]},
		},
	}
	res, err := Marshal(l)
	if err != nil {
		t.Errorf("Failed to marshal entry: %s", err)
	}
	if res != personLDIF {
		t.Errorf("unexpected result: >>%s<<\n", res)
	}
}

func TestMarshalEntries(t *testing.T) {
	l := &LDIF{
		Entries: []*Entry{
			{Entry: entries[0]},
			{Entry: entries[1]},
		},
	}
	res, err := Marshal(l)
	if err != nil {
		t.Errorf("Failed to marshal entry: %s", err)
	}
	if res != ouLDIF+personLDIF {
		t.Errorf("unexpected result: >>%s<<\n", res)
	}
}

func TestMarshalB64(t *testing.T) {
	entryLDIF := `dn: ou=people,dc=example,dc=org
objectClass: top
objectClass: organizationalUnit
ou: people
description:: VGhlIFBlw7ZwbGUgw5ZyZ2FuaXphdGlvbg==

`
	entry := &ldap.Entry{
		DN: "ou=people,dc=example,dc=org",
		Attributes: []*ldap.EntryAttribute{
			{
				Name: "objectClass",
				Values: []string{
					"top",
					"organizationalUnit",
				},
			},
			{
				Name:   "ou",
				Values: []string{"people"},
			},
			{
				Name:   "description",
				Values: []string{"The Peöple Örganization"},
			},
		},
	}
	l := &LDIF{
		Entries: []*Entry{
			{Entry: entry},
		},
	}
	res, err := Marshal(l)
	if err != nil {
		t.Errorf("Failed to marshal entry: %s", err)
	}
	if res != entryLDIF {
		t.Errorf("unexpected result: >>%s<<\n", res)
	}
}

func TestMarshalMod(t *testing.T) {
	modLDIF := `dn: uid=someone,ou=people,dc=example,dc=org
changetype: modify
replace: sn
sn: One
-
add: givenName
givenName: Some
-
delete: mail
-
delete: telephoneNumber
telephoneNumber: 123 456 789 - 0
-

`
	mod := ldap.NewModifyRequest("uid=someone,ou=people,dc=example,dc=org", nil)
	mod.Replace("sn", []string{"One"})
	mod.Add("givenName", []string{"Some"})
	mod.Delete("mail", []string{})
	mod.Delete("telephoneNumber", []string{"123 456 789 - 0"})
	l := &LDIF{
		Entries: []*Entry{
			{Modify: mod},
		},
	}
	res, err := Marshal(l)
	if err != nil {
		t.Errorf("Failed to marshal entry: %s", err)
	}
	if res != modLDIF {
		t.Errorf("unexpected result: >>%s<<", res)
	}
}

func TestMarshalAdd(t *testing.T) {
	addLDIF := `dn: uid=someone,ou=people,dc=example,dc=org
changetype: add
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
uid: someone
cn: Someone
mail: someone@example.org

`
	add := ldap.NewAddRequest("uid=someone,ou=people,dc=example,dc=org", nil)
	for _, a := range entries[1].Attributes {
		add.Attribute(a.Name, a.Values)
	}
	l := &LDIF{
		Entries: []*Entry{
			{Add: add},
		},
	}
	res, err := Marshal(l)
	if err != nil {
		t.Errorf("Failed to marshal entry: %s", err)
	}
	if res != addLDIF {
		t.Errorf("unexpected result: >>%s<<", res)
	}
}

func TestMarshalDel(t *testing.T) {
	delLDIF := `dn: uid=someone,ou=people,dc=example,dc=org
changetype: delete

`
	del := ldap.NewDelRequest("uid=someone,ou=people,dc=example,dc=org", nil)
	l := &LDIF{
		Entries: []*Entry{
			{Del: del},
		},
	}
	res, err := Marshal(l)
	if err != nil {
		t.Errorf("Failed to marshal entry: %s", err)
	}
	if res != delLDIF {
		t.Errorf("unexpected result: >>%s<<", res)
	}
}

func TestDump(t *testing.T) {
	delLDIF := `dn: uid=someone,ou=people,dc=example,dc=org
changetype: delete

`
	del := ldap.NewDelRequest("uid=someone,ou=people,dc=example,dc=org", nil)
	buf := bytes.NewBuffer(nil)
	err := Dump(buf, 0, del)
	if err != nil {
		t.Errorf("Failed to dump entry: %s", err)
	}
	res := buf.String()
	if res != delLDIF {
		t.Errorf("unexpected result: >>%s<<", res)
	}
}
