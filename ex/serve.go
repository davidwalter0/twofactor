/*

# An example using tls/configured service with letsencrypt certs using
# run.example, modify host names and other args as you see fit

export APP_HTTPS=true
export APP_HOST=example.com
export APP_PORT=8443
export APP_CERT=/etc/letsencrypt/live/example.com/cert.pem
export APP_KEY=/etc/letsencrypt/live/example.com/privkey.pem
sudo -E /usr/local/go/bin/go run serve.go &

*/

package main

import (
	"crypto"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/davidwalter0/go-cfg"
	"github.com/davidwalter0/go-mutex"
	"github.com/davidwalter0/twofactor"
	"golang.org/x/net/http2"
)

// debugging may leave unsafe breadcrumbs like files with secure
// runtime info
var debugging = false
var monitor = mutex.NewMutex()

func main() {
	run()
}

func run() {
	var jsonText []byte
	var err error
	if err = cfg.Parse(&app); err != nil {
		log.Fatalf("%v\n", err)
	}

	jsonText, _ = json.MarshalIndent(&app, "", "  ")
	protocol := "https://"

	log.Printf("\nEnvironment configuration\n%v\n", string(jsonText))
	log.Println("Answering requests on " + protocol + app.Host + ":" + app.Port)

	handler := My2FAGeneratorHandler{}
	server := http.Server{
		Addr:    app.Host + ":" + app.Port,
		Handler: &handler,
	}
	http2.ConfigureServer(&server, &http2.Server{})
	err = server.ListenAndServeTLS(app.Cert, app.Key)
	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	}

}

// Digits number of chars 6 or 8 in the token
var Digits = 6

// AccountMap account / email TOTP
type AccountMap map[string]*Auth

// IssuerMap map by issuer of of account/email totp token bytes
type IssuerMap map[string]AccountMap

var issuerMap = make(IssuerMap)

// App application configuration struct
type App struct {
	Cert string
	Key  string
	Host string
	Port string
}

var app App

type My2FAGeneratorHandler struct{}

func (h *My2FAGeneratorHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := strings.Split(r.URL.Path, "/")
	if len(path) > 1 {
		switch path[1] {
		case "key":
			KeyQuery(w, r)
		case "validate":
			Validate(w, r)
		case "qrcode":
			fallthrough
		default:
			Qr2FAGenerator(w, r)
		}
	} else {
		Qr2FAGenerator(w, r)
	}
}

// Results struct to reply from validation
type Results struct {
	Account string
	Issuer  string
	Token   string
	Status  string
}

// KeyReponse key + status for manual otp apps
type KeyReponse struct {
	Key    string
	Status string
}

// Result returns a result struct as json
func Result(account, issuer, token, status string) Results {
	log.Println("account:", account, "issuer:", issuer, "token:", token, "status:", status)
	return Results{Account: account, Issuer: issuer, Token: token, Status: status}
}

// KeyResult returns the key + status as json
func KeyResult(key, status string) KeyReponse {
	log.Println("key:", key, "status:", status)
	return KeyReponse{Key: key, Status: status}
}

// WriteResult of validation to http.ResponseWriter
func WriteResult(account, issuer, token, status string, w http.ResponseWriter, code int) {
	log.Println("WriteResult: account:", account, "issuer:", issuer, "token:", token, "status:", status)
	var results = Result(account, issuer, token, status)
	log.Println("WriteResult > ", results)
	log.Printf("WriteResult > %v\n", results)
	if data, err := json.Marshal(&results); err == nil {
		log.Println(err, string(data))
		if _, err = w.Write(data); err != nil {
			http.Error(w, status, http.StatusNotFound)
		}
	} else {
		log.Println("Marshal failed", err)
	}
}

// Lookup issuer/account in issuerMap for the secrets map
func Lookup(issuer, account string) (auth *Auth, err error) {
	defer monitor.Monitor()()
	if _, ok := issuerMap[issuer]; !ok {
		issuerMap[issuer] = make(AccountMap)
	}
	accountMap := issuerMap[issuer]

	if a, ok := accountMap[account]; !ok {
		if auth = DBLookup(issuer, account); auth == nil {
			err = fmt.Errorf("Issuer %s Account %s not found", issuer, account)
			return
		}
	} else {
		log.Println("************************************************************************")
		log.Println("auth", a)
		log.Println("************************************************************************")
		auth = a
	}
	return
}

// DBLookup go to the persistent storage for this issuer/account add
// to the issuerMap map if found
func DBLookup(issuer, account string) (auth *Auth) {
	auth = NewKey(account, issuer)
	if auth.Exists() {
		auth.Read()
		auth.TotpRestore()
	} else {
		auth = nil
	}
	return
}

// TotpStore encoded types to raw types, enter with otp object initialized
func (auth *Auth) TotpStore() {
	if auth.otp == nil {
		log.Fatalf(`TotpStore: otp nil / not set exiting`)
	}

	var err error
	auth.Key = auth.otp.KeyBase32()
	auth.key = auth.otp.Key()

	if auth.totp, err = auth.otp.ToBytes(); err != nil {
		log.Fatalf(`
otp ToBytes failed for string 
%s
%s
%v
`, auth.otp, auth.totp, err)
	}

	if auth.Totp = base64.StdEncoding.EncodeToString(auth.totp); len(auth.Totp) == 0 {
		log.Fatalf(`
Totp encode failed for string 
%s
%s
`, auth.Totp, auth.totp)
	}

	if auth.png, err = auth.otp.QR(); err != nil {
		log.Fatalf(`
png QR create failed for string 
%s
%s
%v
`, auth.png, auth.Totp, err)
	}

}

// TotpRestore encoded types to raw types
func (auth *Auth) TotpRestore() {
	if len(auth.Totp) == 0 || len(auth.Key) == 0 {
		log.Fatalf(`TotpStore: totp %v len 0 or key %v len 0`, auth.Totp, auth.Key)
	}

	var err error

	if auth.totp, err = base64.StdEncoding.DecodeString(auth.Totp); err != nil {
		log.Fatalf(`
Totp encode failed for string 
%s
%s
%v
`, auth.Totp, auth.totp, err)
	}

	if auth.otp, err = twofactor.TOTPFromBytes(auth.totp, auth.Issuer); err != nil {
		log.Fatalf(`
	otp TOTPFromBytes failed for string
	%s
	%s
	%v
	`, auth.otp, auth.Totp, err)
	}

	auth.key = b32Decode(auth.Key)

	if auth.png, err = auth.otp.QR(); err != nil {
		log.Fatalf(`
png QR create failed for string 
%s
%s
%v
`, auth.png, auth.Totp, err)
	}
}

// ParseTokenArgs parse helper
func ParseTokenArgs(r *http.Request) (token string, err error) {
	token = r.URL.Query().Get("token")
	if token == "" {
		err = errors.New("empty token missing option")
	}
	return
}

// ParseArgs parse helper
func ParseArgs(r *http.Request) (issuer, account string, err error) {
	issuer = r.URL.Query().Get("issuer")
	if issuer == "" {
		err = errors.New("empty issuer missing option")
		return
	}

	account = r.URL.Query().Get("account")
	if account == "" {
		err = errors.New("empty account missing option")
		return
	}
	return
}

// ParseValidationArgs parse helper
func ParseValidationArgs(r *http.Request) (issuer, account, token string, err error) {
	if issuer, account, err = ParseArgs(r); err == nil {
		token, err = ParseTokenArgs(r)
	}
	return
}

// Validate a token requested for account and issuer from request
// string
func Validate(w http.ResponseWriter, r *http.Request) {
	var err error
	var account, issuer, token, status string
	var auth *Auth
	var shouldBe string

	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
	w.Header().Set("Access-Control-Allow-Headers",
		"Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")

	if issuer, account, token, err = ParseValidationArgs(r); err != nil {
		status = fmt.Sprintf("%v", err)
		log.Println(status, http.StatusNotFound)
		WriteResult(account, issuer, token, status, w, http.StatusNotFound)
		return
	}

	if auth, err = Lookup(issuer, account); err != nil {
		status = fmt.Sprintf("%v", err)
		log.Println(status, http.StatusNotFound)
		WriteResult(account, issuer, token, status, w, http.StatusNotFound)
		return
	}

	shouldBe, err = auth.otp.Validate(token)
	if err != nil {
		if debugging {
			status = fmt.Sprintf("Fail %v token %s, wanted %s", err, token, shouldBe)
		} else {
			status = fmt.Sprintf("Fail %v token %s", err, token)
		}
		log.Println(status)
		WriteResult(account, issuer, token, status, w, http.StatusUnauthorized)
		return
	}
	status = "Successfully validated code"
	log.Println(status)
	WriteResult(account, issuer, token, status, w, http.StatusAccepted)
	return
}

// Exists check for entry of auth object in database
func (auth *Auth) Exists() (ok bool) {
	if auth.Count() == 1 {
		log.Println("We have this guy in the db, skipping.")
		ok = true
	} else {
		log.Println("Who's this guy?")
	}
	return
}

// Qr2FAGenerator create & return png
func Qr2FAGenerator(w http.ResponseWriter, r *http.Request) {
	var err error
	var account, issuer, status string
	var auth *Auth

	log.Println("https://"+app.Host+":"+app.Port, r.Body, r)
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
	w.Header().Set("Access-Control-Allow-Headers",
		"Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")

	if issuer, account, err = ParseArgs(r); err != nil {
		status = fmt.Sprintf("%v", err)
		log.Println(status, http.StatusNotFound)
		http.Error(w, status, http.StatusNotFound)
		return
	}

	if auth, err = Lookup(issuer, account); err != nil {
		auth = NewKey(account, issuer)

		if auth.otp, err = twofactor.NewTOTP(account, issuer, crypto.SHA1, Digits); err != nil {
			log.Println(err)
			http.Error(w, fmt.Sprintf("%v TOTP call failed", err), http.StatusInternalServerError)
			return
		}
		auth.TotpStore()
		auth.Digits = Digits
		auth.Hash = "sha1"
		auth.Create()
		auth.Read()
		defer monitor.Monitor()()
		if _, ok := issuerMap[issuer]; !ok {
			issuerMap[issuer] = make(AccountMap)
		}

		log.Println("Who's this guy?")
		issuerMap[issuer][account] = auth
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Content-Length", strconv.Itoa(len(auth.png)))

	if debugging { // unsafe option
		_ = ioutil.WriteFile(auth.GUID+".png", auth.png, 0644)
	}

	log.Println("raw key: ", auth.key)
	log.Println("b32key : ", auth.otp.KeyBase32())
	log.Println(b64Encode(auth.totp))

	if _, err = w.Write(auth.png); err != nil {
		http.Error(w, "", http.StatusNotFound)
		return
	}
}

// KeyQuery .../key/?account=&issuer... -> key+status
func KeyQuery(w http.ResponseWriter, r *http.Request) {
	var account, issuer, status string

	var auth *Auth
	var err error
	var data []byte

	log.Println("https://"+app.Host+":"+app.Port, r.Body, r)
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
	w.Header().Set("Access-Control-Allow-Headers",
		"Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")

	if issuer, account, err = ParseArgs(r); err != nil {
		status = fmt.Sprintf("%v", err)
		log.Println(status, http.StatusNotFound)
		http.Error(w, status, http.StatusNotFound)
		return
	}

	if auth, err = Lookup(issuer, account); err == nil {
		log.Println(auth.Key)
		status = "Found issuer/account key"
		log.Println(status)
		results := KeyResult(auth.Key, status)
		if data, err = json.Marshal(&results); err == nil {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Content-Type", strconv.Itoa(len(data)))
			if _, err = w.Write(data); err != nil {
				http.Error(w, status, http.StatusNotFound)
			}
		} else {
			status = fmt.Sprintf("Marshal failed %v", err)
			log.Println(status)
			http.Error(w, status, http.StatusNotFound)
		}
	} else {
		status = fmt.Sprintf("issuer/account not found %v", err)
		log.Println(status, http.StatusNotFound)
		http.Error(w, status, http.StatusNotFound)
	}
	return

}

func b32Encode(in []byte) (out string) {
	out = base32.StdEncoding.EncodeToString(in)
	return
}
func b64Encode(in []byte) (out string) {
	out = base64.StdEncoding.EncodeToString(in)
	return
}

func b32Decode(in string) (out []byte) {
	var err error
	out, err = base32.StdEncoding.DecodeString(in)
	CheckError(err)
	return
}

func b64Decode(in string) (out []byte) {
	var err error
	out, err = base64.StdEncoding.DecodeString(in)
	CheckError(err)
	return
}

// CheckError standardize error handling
func CheckError(err error) {
	if err != nil {
		log.Println(err)
		panic(err)
	}
}
