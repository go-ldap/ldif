package ldif_test

import (
	"testing"

	"gopkg.in/ldap.v2/ldif"
)

var ldifRFC2849Example6 = `version: 1
# Add a new entry
dn: cn=Fiona Jensen, ou=Marketing, dc=airius, dc=com
changetype: add
objectclass: top
objectclass: person
objectclass: organizationalPerson
cn: Fiona Jensen
sn: Jensen
uid: fiona
telephonenumber: +1 408 555 1212
# jpegphoto:< file:///usr/local/directory/photos/fiona.jpg

# Delete an existing entry
dn: cn=Robert Jensen, ou=Marketing, dc=airius, dc=com
changetype: delete

# Modify an entry's relative distinguished name
#dn: cn=Paul Jensen, ou=Product Development, dc=airius, dc=com
#changetype: modrdn
#newrdn: cn=Paula Jensen
#deleteoldrdn: 1

# Rename an entry and move all of its children to a new location in
# the directory tree (only implemented by LDAPv3 servers).
#dn: ou=PD Accountants, ou=Product Development, dc=airius, dc=com
#changetype: modrdn
#newrdn: ou=Product Development Accountants
#deleteoldrdn: 0
#newsuperior: ou=Accounting, dc=airius, dc=com

# Modify an entry: add an additional value to the postaladdress
# attribute, completely delete the description attribute, replace
# the telephonenumber attribute with two values, and delete a specific
# value from the facsimiletelephonenumber attribute
dn: cn=Paula Jensen, ou=Product Development, dc=airius, dc=com
changetype: modify
add: postaladdress
postaladdress: 123 Anystreet $ Sunnyvale, CA $ 94086
-
# the example in the RFC has an empty line here, I don't think that's allowed...
delete: description
-
replace: telephonenumber
telephonenumber: +1 408 555 1234
telephonenumber: +1 408 555 5678
-
delete: facsimiletelephonenumber
facsimiletelephonenumber: +1 408 555 9876
-

# Modify an entry: replace the postaladdress attribute with an empty
# set of values (which will cause the attribute to be removed), and
# delete the entire description attribute. Note that the first will
# always succeed, while the second will only succeed if at least
# one value for the description attribute is present.
dn: cn=Ingrid Jensen, ou=Product Support, dc=airius, dc=com
changetype: modify
replace: postaladdress
-
delete: description
-
`

func TestLDIFParseRFC2849Example6(t *testing.T) {
	l, err := ldif.Parse(ldifRFC2849Example6)
	if err != nil {
		t.Errorf("Failed to parse RFC 2849 example #6: %s", err)
	}
	if len(l.Entries) != 4 { // != 6
		t.Errorf("invalid number of entries parsed: %d", len(l.Entries))
	}
	if l.Entries[3].Modify == nil {
		t.Errorf("last entry not a modify request")
	}
	if l.Entries[3].Modify.DeleteAttributes[0].Type != "description" {
		t.Errorf("RFC 2849 example 6: no deletion of description in last entry")
	}
	if l.Entries[2].Modify.ReplaceAttributes[0].Type != "telephonenumber" &&
		l.Entries[2].Modify.ReplaceAttributes[0].Vals[1] != "+1 408 555 5678" {
		t.Errorf("RFC 2849 example 6: no replacing of telephonenumber")
	}
}
