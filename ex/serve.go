/*
An example using tls/configured service with letsencrypt certs

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
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/davidwalter0/go-cfg"
	"github.com/davidwalter0/twofactor"
	"golang.org/x/net/http2"
)

func main() {
	run()
}

// Digits number of chars 6 or 8 in the token
var Digits = 6

// PngTotp pair of elements
type PngTotp struct {
	Png  []byte
	Totp []byte
}

// UserMap account / email TOTP
type UserMap map[string]PngTotp

// IssuerUserTOTP map by issuer of of account/email totp token bytes
type IssuerUserTOTP map[string]UserMap

var issuerUserTOTP = make(IssuerUserTOTP)

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

// Result returns a result struct as json
func Result(account, issuer, token, status string) Results {
	log.Println("account:", account, "issuer:", issuer, "token:", token, "status:", status)
	return Results{Account: account, Issuer: issuer, Token: token, Status: status}
}

// WriteResult of validation to http.ResponseWriter
func WriteResult(account, issuer, token, status string, w http.ResponseWriter, code int) {
	// var data []byte
	// var err error
	log.Println("WriteResult: account:", account, "issuer:", issuer, "token:", token, "status:", status)
	//	var results Results = Result(account, issuer, token, status)
	var results = Result(account, issuer, token, status)
	log.Println("WriteResult > ", results)
	log.Printf("WriteResult > %v\n", results)
	if data, err := json.Marshal(&results); err == nil {
		log.Println(err, string(data))
		if _, err = w.Write(data); err != nil {
			http.Error(w, status, http.StatusInternalServerError)
		}
	} else {
		log.Println("Marshal failed", err)
	}

}

// Validate a token requested for account and issuer from request string
func Validate(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
	w.Header().Set("Access-Control-Allow-Headers",
		"Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")

	var account, issuer, token, status string
	token = r.URL.Query().Get("token")
	if token == "" {
		status = "empty token missing option"
		log.Println(status, http.StatusInternalServerError)
		WriteResult(account, issuer, token, status, w, http.StatusInternalServerError)
		return
	}

	account = r.URL.Query().Get("account")
	if account == "" {
		status = "empty account missing option"
		log.Println(status, http.StatusInternalServerError)
		WriteResult(account, issuer, token, status, w, http.StatusInternalServerError)
		return
	}
	issuer = r.URL.Query().Get("issuer")
	if issuer == "" {
		status = "empty issuer missing option"
		log.Println(status, http.StatusInternalServerError)
		WriteResult(account, issuer, token, status, w, http.StatusInternalServerError)
		return
	}

	var auth = NewKey(account, issuer)

	if auth.Exists() {
		auth.Read()
		if _, ok := issuerUserTOTP[issuer]; !ok {
			issuerUserTOTP[issuer] = make(UserMap)
		}
		var err error
		var totpBytes []byte

		if totpBytes, err = base64.StdEncoding.DecodeString(auth.Totp); err != nil {
			log.Fatalf(`
Totp decode failed for string 
%s
%s
%v
`, auth.Totp, totpBytes, err)
		}
		issuerUserTOTP[issuer][account] = PngTotp{Png: []byte{}, Totp: totpBytes}
	}
	if userTOTP, ok := issuerUserTOTP[issuer]; ok {
		if pngTotp, ok := userTOTP[account]; ok {

			totp, err := twofactor.TOTPFromBytes(pngTotp.Totp, issuer)
			log.Printf("Attempting validation for %s %s %s\n", issuer, account, token)
			if err != nil {
				status := fmt.Sprintf("Unable to create OTP from bytes %s %v", token, err)
				log.Println(status)
				WriteResult(account, issuer, token, status, w, http.StatusInternalServerError)
				return
			}
			err = totp.Validate(token)
			if err != nil {
				status := fmt.Sprintf("Fail %v token %s", err, token)
				log.Println(status)
				WriteResult(account, issuer, token, status, w, http.StatusInternalServerError)
				return
			}
			// log.Println("Successfully validated code")
			// w.Write([]byte("Successfully validated code"))
			status = "Successfully validated code"
			log.Println(status)
			WriteResult(account, issuer, token, status, w, http.StatusAccepted)
			return
		}
		status = fmt.Sprintf("User account %s not registered for issuer %s", account, issuer)
		log.Println(status)
		WriteResult(account, issuer, token, status, w, http.StatusInternalServerError)
		return
	} // early returns so this doesn't require an else block
	status = fmt.Sprintf("Issuer not found %s", issuer)
	log.Println(status)
	WriteResult(account, issuer, token, status, w, http.StatusInternalServerError)

	return
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

func Qr2FAGenerator(w http.ResponseWriter, r *http.Request) {

	log.Println("http://"+app.Host+":"+app.Port, r.Body, r)
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
	w.Header().Set("Access-Control-Allow-Headers",
		"Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")

	account := r.URL.Query().Get("account")
	if account == "" {
		log.Println("empty account missing option", http.StatusInternalServerError)
		http.Error(w, "empty account missing option", http.StatusInternalServerError)
		return
	}
	issuer := r.URL.Query().Get("issuer")
	if issuer == "" {
		log.Println("empty issuer missing option", http.StatusInternalServerError)
		http.Error(w, "empty issuer missing option", http.StatusInternalServerError)
		return
	}

	otp, err := twofactor.NewTOTP(account, issuer, crypto.SHA1, Digits)
	if err != nil {
		fmt.Println(err)
		log.Println(err)
		http.Error(w, fmt.Sprintf("%v TOTP call failed", err), http.StatusInternalServerError)
	}
	qrBytes, err := otp.QR()
	if err != nil {
		fmt.Println(err)
		log.Println(err)
		http.Error(w, fmt.Sprintf("%v QR code generation failed", err), http.StatusInternalServerError)
	}

	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Content-Length", strconv.Itoa(len(qrBytes)))

	// account is assumed to be an email for these purposes
	if _, ok := issuerUserTOTP[issuer]; !ok {
		issuerUserTOTP[issuer] = make(UserMap)
	}

	if totpBytes, err := otp.ToBytes(); err == nil {
		issuerUserTOTP[issuer][account] = PngTotp{Png: qrBytes, Totp: totpBytes}
		key := otp.Key()

		var auth = NewKey(account, issuer)

		if auth.Exists() {
			log.Println("We have this guy in the db, skipping.")
			auth.Totp = base64.StdEncoding.EncodeToString(totpBytes)
			auth.Key = otp.KeyBase32()
			auth.Digits = Digits
			auth.Hash = "sha1"
			auth.Update()
		} else {
			log.Println("Who's this guy?")
			auth.Totp = base64.StdEncoding.EncodeToString(totpBytes)
			auth.Key = otp.KeyBase32()
			auth.Digits = Digits
			auth.Hash = "sha1"
			auth.Create()
		}
		_ = ioutil.WriteFile(auth.GUID+".png", qrBytes, 0644)

		log.Println("key: ", fmt.Sprintf("%0x", (key)))
		log.Println("raw key: ", key)
		log.Println("b32key : ", otp.KeyBase32())
		log.Println(base64.StdEncoding.EncodeToString(totpBytes))
		log.Println(base32.StdEncoding.EncodeToString(totpBytes))
		otpText, err := otp.OTP()
		if err != nil {
			log.Println(err)
		}
		log.Println("otp: ", otpText)

		if _, err = w.Write(qrBytes); err != nil {
			http.Error(w, "", http.StatusInternalServerError)
			return
		}
	} else {
		fmt.Println(err)
		log.Println(err)
	}
}
