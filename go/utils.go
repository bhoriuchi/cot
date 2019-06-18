package cot

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

var bearerRx = regexp.MustCompile(`(?i)^(Bearer|JWT)\s+(.+)$`)

// GetJwtFromRequest gets a jwt from the request
// accepts Authroization headers for Bearer and JWT
// also accepts Cookie with JWT
func GetJwtFromRequest(r *http.Request, cookieName string) (string, error) {
	match := bearerRx.FindAllStringSubmatch(r.Header.Get("Authorization"), -1)
	if len(match) > 0 {
		return strings.TrimSpace(match[0][2]), nil
	}

	if cookieName != "" {
		cookie, err := r.Cookie(cookieName)
		if err == nil {
			return strings.TrimSpace(cookie.Value), nil
		}
	}

	return "", fmt.Errorf("failed to extract token from request")
}
