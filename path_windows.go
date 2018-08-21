package ldif

import "net/url"
import "strings"

func toPath(u *url.URL) string {
	return strings.TrimPrefix(u.Path, "/")
}
