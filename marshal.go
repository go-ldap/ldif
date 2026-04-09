package ldif

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

var foldWidth = 76

// ErrMixed is the error, that we cannot mix change records and content
// records in one LDIF
var ErrMixed = errors.New("cannot mix change records and content records")

// Marshal returns an LDIF string from the given LDIF.
//
// The default line lenght is 76 characters. This can be changed by setting
// the fw parameter to something else than 0.
// For a fold width < 0, no folding will be done, with 0, the default is used.
func Marshal(l *LDIF) (data string, err error) {
	var builder strings.Builder
	err = MarshalStreaming(l, &builder)
	if err != nil {
		return "", err
	}
	return builder.String(), nil
}

func MarshalStreaming(l *LDIF, writer io.Writer) (err error) {
	hasEntry := false
	hasChange := false

	if l.Version > 0 {
		_, err := io.WriteString(writer, "version: 1\n")
		if err != nil {
			return err
		}
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

			_, err := io.WriteString(writer, foldLine("dn: "+e.Add.DN, fw)+"\n")
			if err != nil {
				return err
			}

			_, err = io.WriteString(writer, "changetype: add\n")
			if err != nil {
				return err
			}

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

					_, err = io.WriteString(writer, foldLine(add.Type+col+ev, fw)+"\n")
					if err != nil {
						return err
					}
				}
			}

		case e.Del != nil:
			hasChange = true
			if hasEntry {
				return ErrMixed
			}

			_, err = io.WriteString(writer, foldLine("dn: "+e.Del.DN, fw)+"\n")
			if err != nil {
				return err
			}

			_, err = io.WriteString(writer, "changetype: delete\n")
			if err != nil {
				return err
			}

		case e.Modify != nil:
			hasChange = true
			if hasEntry {
				return ErrMixed
			}

			_, err = io.WriteString(writer, foldLine("dn: "+e.Modify.DN, fw)+"\n")
			if err != nil {
				return err
			}

			_, err = io.WriteString(writer, "changetype: modify\n")
			if err != nil {
				return err
			}

			for _, mod := range e.Modify.Changes {
				switch mod.Operation {
				// add operation - https://tools.ietf.org/html/rfc4511#section-4.6
				case 0:
					if len(mod.Modification.Vals) == 0 {
						return errors.New("changetype 'modify', op 'add' requires non empty value list")
					}

					_, err = io.WriteString(writer, "add: "+mod.Modification.Type+"\n")
					if err != nil {
						return err
					}

					for _, v := range mod.Modification.Vals {
						ev, t := encodeValue(v)
						col := ": "
						if t {
							col = ":: "
						}

						_, err = io.WriteString(writer, foldLine(mod.Modification.Type+col+ev, fw)+"\n")
						if err != nil {
							return err
						}
					}
					_, err = io.WriteString(writer, "-\n")
					if err != nil {
						return err
					}
				// delete operation - https://tools.ietf.org/html/rfc4511#section-4.6
				case 1:
					_, err = io.WriteString(writer, "delete: "+mod.Modification.Type+"\n")
					if err != nil {
						return err
					}

					for _, v := range mod.Modification.Vals {
						ev, t := encodeValue(v)
						col := ": "
						if t {
							col = ":: "
						}
						_, err = io.WriteString(writer, foldLine(mod.Modification.Type+col+ev, fw)+"\n")
						if err != nil {
							return err
						}
					}
					_, err = io.WriteString(writer, "-\n")
					if err != nil {
						return err
					}
				// replace operation - https://tools.ietf.org/html/rfc4511#section-4.6
				case 2:
					if len(mod.Modification.Vals) == 0 {
						return errors.New("changetype 'modify', op 'replace' requires non empty value list")
					}
					_, err = io.WriteString(writer, "replace: "+mod.Modification.Type+"\n")
					if err != nil {
						return err
					}
					for _, v := range mod.Modification.Vals {
						ev, t := encodeValue(v)
						col := ": "
						if t {
							col = ":: "
						}

						_, err = io.WriteString(writer, foldLine(mod.Modification.Type+col+ev, fw)+"\n")
						if err != nil {
							return err
						}
					}
					_, err = io.WriteString(writer, "-\n")
					if err != nil {
						return err
					}
				default:
					return fmt.Errorf("invalid type %s in modify request", mod.Modification.Type)
				}
			}
		default:
			hasEntry = true
			if hasChange {
				return ErrMixed
			}

			_, err = io.WriteString(writer, foldLine("dn: "+e.Entry.DN, fw)+"\n")
			if err != nil {
				return err
			}

			for _, av := range e.Entry.Attributes {
				for _, v := range av.Values {
					ev, t := encodeValue(v)
					col := ": "
					if t {
						col = ":: "
					}
					_, err = io.WriteString(writer, foldLine(av.Name+col+ev, fw)+"\n")
					if err != nil {
						return err
					}
				}
			}
		}
		_, err = io.WriteString(writer, "\n")
		if err != nil {
			return err
		}
	}
	return nil
}

func encodeValue(value string) (string, bool) {
	required := false
	for _, r := range value {
		if r < ' ' || r > '~' || value[len(value)-1:] == " " { // ~ = 0x7E, <DEL> = 0x7F
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
	err = MarshalStreaming(l, fh)
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
