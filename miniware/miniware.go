// Steve Phillips / elimisteve
// 2017.04.01

package miniware

import (
	"errors"
	"net/http"
	"strings"
	"sync"

	log "github.com/Sirupsen/logrus"
	"github.com/cathalgarvey/go-minilock/taber"
	gorillacontext "github.com/gorilla/context"
)

const (
	MINILOCK_ID_KEY      = "minilock_id"
	MINILOCK_KEYPAIR_KEY = "minilock_keypair"
)

var (
	ErrAuthTokenNotFound = errors.New("Auth token not found")
)

type Mapper struct {
	lock sync.RWMutex
	m    map[string]string // map[authToken]minilockID
}

func NewMapper() *Mapper {
	return &Mapper{m: map[string]string{}}
}

func (m *Mapper) GetMinilockID(authToken string) (string, error) {
	m.lock.RLock()
	defer m.lock.RUnlock()

	mID, ok := m.m[authToken]
	if !ok {
		return "", ErrAuthTokenNotFound
	}
	return mID, nil
}

func (m *Mapper) SetMinilockID(authToken, mID string) error {
	m.lock.Lock()
	defer m.lock.Unlock()

	m.m[authToken] = mID
	return nil
}

func Auth(h http.Handler, m *Mapper, writeError func(w http.ResponseWriter, errStr string, secretErr error, statusCode int) error) func(w http.ResponseWriter, req *http.Request) {
	return func(w http.ResponseWriter, req *http.Request) {
		authToken := parseAuthTokenFromHeader(req)
		if authToken == "" {
			writeError(w, "Auth token missing", nil, http.StatusUnauthorized)
			return
		}

		mID, err := m.GetMinilockID(authToken)
		if err != nil {
			status := http.StatusInternalServerError
			if err == ErrAuthTokenNotFound {
				status = http.StatusUnauthorized
			}
			writeError(w, "Error authorizing you", err, status)
			return
		}

		log.Infof("`%s` just authed successfully; auth token: `%s`\n", mID,
			authToken)

		// TODO: Update auth token's TTL/lease to be 1 hour from
		// _now_, not just 1 hour since when they first logged in

		keypair, err := taber.FromID(mID)
		if err != nil {
			writeError(w, "Your miniLock ID is invalid?...", err,
				http.StatusInternalServerError)
			return
		}

		gorillacontext.Set(req, MINILOCK_ID_KEY, mID)
		gorillacontext.Set(req, MINILOCK_KEYPAIR_KEY, keypair)

		h.ServeHTTP(w, req)
	}
}

func parseAuthTokenFromHeader(req *http.Request) string {
	bearerAndToken := req.Header.Get("Authorization")
	token := strings.TrimLeft(bearerAndToken, "Bearer ")
	return token
}
