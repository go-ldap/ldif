package ldif

import (
	"encoding/base64"
	"errors"
	"fmt"
	"bufio"
	"bytes"
	"gopkg.in/ldap.v2"
	"io"
)

var foldWidth = 76

// ErrMixed is the error, that we cannot mix change records and content
// records in one LDIF
var ErrMixed = errors.New("cannot mix change records and content records")

// Marshal writes LDIF string to the specified Buffer.
//
// The default line lenght is 76 characters. This can be changed by setting
// the fw parameter to something else than 0.
// For a fold width < 0, no folding will be done, with 0, the default is used.
func MarshalBuffer(l *LDIF, output io.Writer) (err error) {
	hasEntry := false
	hasChange := false
	buffer := bufio.NewWriter(output)
	if l.Version > 0 {
		buffer.WriteString("version: 1\n")
	}
	

	fw := l.FoldWidth
	if fw == 0 {
		fw = foldWidth
	}
	for _, e := range l.Entries {
		switch {
		case e.Add != nil:
			hasChange = true
			if hasEntry {
				return ErrMixed
			}
			buffer.WriteString(foldLine("dn: "+e.Add.DN, fw) + "\n")
			buffer.WriteString("changetype: add\n")
			for _, add := range e.Add.Attributes {
				if len(add.Vals) == 0 {
					return errors.New("changetype 'add' requires non empty value list")
				}
				for _, v := range add.Vals {
					ev, t := encodeValue(v)
					col := ": "
					if t {
						col = ":: "
					}
					buffer.WriteString(foldLine(add.Type+col+ev, fw) + "\n")
				}
			}

		case e.Del != nil:
			hasChange = true
			if hasEntry {
				return ErrMixed
			}
			buffer.WriteString(foldLine("dn: "+e.Del.DN, fw) + "\n")
			buffer.WriteString("changetype: delete\n")

		case e.Modify != nil:
			hasChange = true
			if hasEntry {
				return ErrMixed
			}
			buffer.WriteString(foldLine("dn: "+e.Modify.DN, fw) + "\n")
			buffer.WriteString("changetype: modify\n")
			for _, mod := range e.Modify.AddAttributes {
				if len(mod.Vals) == 0 {
					return errors.New("changetype 'modify', op 'add' requires non empty value list")
				}

				buffer.WriteString("add: " + mod.Type + "\n")
				for _, v := range mod.Vals {
					ev, t := encodeValue(v)
					col := ": "
					if t {
						col = ":: "
					}
					buffer.WriteString(foldLine(mod.Type+col+ev, fw) + "\n")
				}
				buffer.WriteString("-\n")
			}
			for _, mod := range e.Modify.DeleteAttributes {
				buffer.WriteString("delete: " + mod.Type + "\n")
				for _, v := range mod.Vals {
					ev, t := encodeValue(v)
					col := ": "
					if t {
						col = ":: "
					}
					buffer.WriteString(foldLine(mod.Type+col+ev, fw) + "\n")
				}
				buffer.WriteString("-\n")
			}
			for _, mod := range e.Modify.ReplaceAttributes {
				if len(mod.Vals) == 0 {
					return errors.New("changetype 'modify', op 'replace' requires non empty value list")
				}
				buffer.WriteString("replace: " + mod.Type + "\n")
				for _, v := range mod.Vals {
					ev, t := encodeValue(v)
					col := ": "
					if t {
						col = ":: "
					}
					buffer.WriteString(foldLine(mod.Type+col+ev, fw) + "\n")
				}
				buffer.WriteString("-\n")
			}

		default:
			hasEntry = true
			if hasChange {
				return ErrMixed
			}
			buffer.WriteString(foldLine("dn: "+e.Entry.DN, fw) + "\n")
			for _, av := range e.Entry.Attributes {
				for _, v := range av.Values {
					ev, t := encodeValue(v)
					col := ": "
					if t {
						col = ":: "
					}
					buffer.WriteString(foldLine(av.Name+col+ev, fw) + "\n")
				}
			}
		}
		buffer.WriteString("\n")
	}
	buffer.Flush()
	return nil
}

// Marshal returns an LDIF string from the given LDIF.
func Marshal(l *LDIF) (data string, err error) {
	temp := new(bytes.Buffer)
	err2 := MarshalBuffer(l, temp)
	if err2 == nil {
		return temp.String(), nil
	}else {
		return "", err2
	}
}

func encodeValue(value string) (string, bool) {
	required := false
	for _, r := range value {
		if r < ' ' || r > '~' { // ~ = 0x7E, <DEL> = 0x7F
			required = true
			break
		}
	}
	if !required {
		return value, false
	}
	return base64.StdEncoding.EncodeToString([]byte(value)), true
}

func foldLine(line string, fw int) (folded string) {
	if fw < 0 {
		return line
	}
	if len(line) <= fw {
		return line
	}

	folded = line[:fw] + "\n"
	line = line[fw:]

	for len(line) > fw-1 {
		folded += " " + line[:fw-1] + "\n"
		line = line[fw-1:]
	}

	if len(line) > 0 {
		folded += " " + line
	}
	return
}

// Dump writes the given entries to the io.Writer.
//
// The entries argument can be *ldap.Entry or a mix of *ldap.AddRequest,
// *ldap.DelRequest, *ldap.ModifyRequest and *ldap.ModifyDNRequest or slices
// of any of those.
//
// See Marshal() for the fw argument.
func Dump(fh io.Writer, fw int, entries ...interface{}) error {
	l, err := ToLDIF(entries...)
	if err != nil {
		return err
	}
	l.FoldWidth = fw
	str, err := Marshal(l)
	if err != nil {
		return err
	}
	_, err = fh.Write([]byte(str))
	return err
}

// ToLDIF puts the given arguments in an LDIF struct and returns it.
//
// The entries argument can be *ldap.Entry or a mix of *ldap.AddRequest,
// *ldap.DelRequest, *ldap.ModifyRequest and *ldap.ModifyDNRequest or slices
// of any of those.
func ToLDIF(entries ...interface{}) (*LDIF, error) {
	l := &LDIF{}
	for _, e := range entries {
		switch e.(type) {
		case []*ldap.Entry:
			for _, en := range e.([]*ldap.Entry) {
				l.Entries = append(l.Entries, &Entry{Entry: en})
			}

		case *ldap.Entry:
			l.Entries = append(l.Entries, &Entry{Entry: e.(*ldap.Entry)})

		case []*ldap.AddRequest:
			for _, en := range e.([]*ldap.AddRequest) {
				l.Entries = append(l.Entries, &Entry{Add: en})
			}

		case *ldap.AddRequest:
			l.Entries = append(l.Entries, &Entry{Add: e.(*ldap.AddRequest)})

		case []*ldap.DelRequest:
			for _, en := range e.([]*ldap.DelRequest) {
				l.Entries = append(l.Entries, &Entry{Del: en})
			}

		case *ldap.DelRequest:
			l.Entries = append(l.Entries, &Entry{Del: e.(*ldap.DelRequest)})

		case []*ldap.ModifyRequest:
			for _, en := range e.([]*ldap.ModifyRequest) {
				l.Entries = append(l.Entries, &Entry{Modify: en})
			}
		case *ldap.ModifyRequest:
			l.Entries = append(l.Entries, &Entry{Modify: e.(*ldap.ModifyRequest)})

		default:
			return nil, fmt.Errorf("unsupported type %T", e)
		}
	}
	return l, nil
}
