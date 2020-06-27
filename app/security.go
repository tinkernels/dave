package app

import (
	"context"
	"fmt"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
	"net/http"
	"os"
	"strings"
)

type contextKey int

var authInfoKey contextKey

type hijackRet int
type opDepth string

const adminUserNmae = "admin"

const (
	opDepth1        = "1"
	opDepthInfinite = "infinity"
)

const (
	hijackSkip     = 0
	hijackModify   = 1
	hijackTakeover = 2
)

// AuthInfo holds the username and authentication status
type AuthInfo struct {
	Username      string
	Authenticated bool
}

// authWebdavHandlerFunc is a type definition which holds a context and application reference to
// match the AuthWebdavHandler interface.
type authWebdavHandlerFunc func(c context.Context, w http.ResponseWriter, r *http.Request, a *App)

// ServeHTTP simply calls the AuthWebdavHandlerFunc with given parameters
func (f authWebdavHandlerFunc) ServeHTTP(c context.Context, w http.ResponseWriter, r *http.Request, a *App) {
	f(c, w, r, a)
}

// NewBasicAuthWebdavHandler creates a new http handler with basic auth features.
// The handler will use the application config for user and password lookups.
func NewBasicAuthWebdavHandler(a *App) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.Background()
		handlerFunc := authWebdavHandlerFunc(handle)
		handlerFunc.ServeHTTP(ctx, w, r, a)
	})
}

func authenticate(config *Config, username, password string) (*AuthInfo, error) {
	if !config.AuthenticationNeeded() {
		return &AuthInfo{Username: "", Authenticated: false}, nil
	}

	if username == "" || password == "" {
		return &AuthInfo{Username: username, Authenticated: false}, errors.New("username not found or password empty")
	}

	user := config.Users[username]
	if user == nil {
		return &AuthInfo{Username: username, Authenticated: false}, errors.New("user not found")
	}

	err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
	if err != nil {
		return &AuthInfo{Username: username, Authenticated: false}, errors.New("Password doesn't match")
	}

	return &AuthInfo{Username: username, Authenticated: true}, nil
}

// AuthFromContext returns information about the authentication state of the current user.
func AuthFromContext(ctx context.Context) *AuthInfo {
	info, ok := ctx.Value(authInfoKey).(*AuthInfo)
	if !ok {
		return nil
	}

	return info
}

func handle(ctx context.Context, w http.ResponseWriter, r *http.Request, app *App) {
	// if there are no users, we don't need authentication here
	if !app.Config.AuthenticationNeeded() {
		app.Handler.ServeHTTP(w, r.WithContext(ctx))
		return
	}

	username, password, ok := httpAuth(r, app.Config)
	if !ok {
		writeUnauthorized(w, app.Config.Realm)
		return
	}

	authInfo, err := authenticate(app.Config, username, password)
	if err != nil {
		log.WithField("user", username).Warn(err.Error())
	}

	if authInfo != nil && !authInfo.Authenticated {
		writeUnauthorized(w, app.Config.Realm)
		return
	}

	ctx = context.WithValue(ctx, authInfoKey, authInfo)
	if hijack(ctx, w, r, app) == hijackTakeover {
		return
	}
	app.Handler.ServeHTTP(w, r.WithContext(ctx))
}

func httpAuth(r *http.Request, config *Config) (string, string, bool) {
	if config.AuthenticationNeeded() {
		username, password, ok := r.BasicAuth()
		return username, password, ok
	}

	return "", "", true
}

func writeUnauthorized(w http.ResponseWriter, realm string) {
	w.Header().Set("WWW-Authenticate", "Basic realm="+realm)
	w.WriteHeader(http.StatusUnauthorized)
	_, _ = w.Write([]byte(fmt.Sprintf("%d %s", http.StatusUnauthorized, "Unauthorized")))
}

func hijack(ctx context.Context, w http.ResponseWriter, r *http.Request, app *App) hijackRet {
	authInfo := AuthFromContext(ctx)
	var reqPath string
	if app.Handler.Prefix == "" {
		reqPath = r.URL.Path
	} else if path := strings.TrimPrefix(r.URL.Path, app.Handler.Prefix);
		len(path) < len(r.URL.Path) {
		reqPath = path
	} else {
		return hijackSkip
	}

	file, err := app.Handler.FileSystem.OpenFile(ctx, reqPath, os.O_RDONLY, 0)
	var fi os.FileInfo
	if (file == nil || err != nil) && authInfo.Username != adminUserNmae {
		rejectRequest(w)
		return hijackTakeover
	} else {
		fi, err = app.Handler.FileSystem.Stat(ctx, reqPath)
		if (fi == nil || err != nil) && authInfo.Username != adminUserNmae {
			rejectRequest(w)
			return hijackTakeover
		}
	}

	switch r.Method {
	case "GET":
		if fi != nil && fi.IsDir() {
			pathResolver := &Dir{Config: app.Config}
			filePath := pathResolver.resolve(ctx, reqPath)
			http.ServeFile(w, r, filePath)
			return hijackTakeover
		}
		break
	case "COPY", "MOVE":
		if authInfo.Username != adminUserNmae {
			rejectRequest(w)
			return hijackTakeover
		}
		if hdr := r.Header.Get("Depth"); hdr == "" {
			r.Header.Set("Depth", opDepthInfinite)
			return hijackModify
		}
		break
	case "PROPFIND":
		if hdr := r.Header.Get("Depth"); hdr == "" {
			r.Header.Set("Depth", opDepth1)
			return hijackModify
		}
		break
	case "HEAD", "OPTIONS":
		return hijackSkip
	case "DELETE", "POST", "PUT", "MKCOL", "LOCK", "UNLOCK", "PROPPATCH":
		if authInfo.Username != adminUserNmae {
			rejectRequest(w)
			return hijackTakeover
		} else {
			return hijackSkip
		}
	default:
		rejectRequest(w)
		return hijackTakeover
	}
	return hijackSkip
}

func rejectRequest(w http.ResponseWriter) {
	w.WriteHeader(http.StatusForbidden)
	_, _ = w.Write([]byte(fmt.Sprintf("%d %s", http.StatusForbidden, "StatusForbidden")))
}

// GenHash generates a bcrypt hashed password string
func GenHash(password []byte) string {
	pw, err := bcrypt.GenerateFromPassword(password, 10)
	if err != nil {
		log.Fatal(err)
	}

	return string(pw)
}
