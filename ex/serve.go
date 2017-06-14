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
	"encoding/json"
	"fmt"
	"github.com/davidwalter0/envflagstructconfig"
	"github.com/davidwalter0/twofactor"
	"golang.org/x/net/http2"
	"log"
	"net/http"
	"strconv"
	"strings"
)

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

// Validate a token requested for account and issuer from request string
func Validate(w http.ResponseWriter, r *http.Request) {

	token := r.URL.Query().Get("token")
	if token == "" {
		log.Println("empty token missing option", http.StatusInternalServerError)
		http.Error(w, "empty token missing option", http.StatusInternalServerError)
		return
	}

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
	if userTOTP, ok := issuerUserTOTP[issuer]; ok {
		if pngTotp, ok := userTOTP[account]; ok {
			totp, err := twofactor.TOTPFromBytes(pngTotp.Totp, issuer)
			log.Printf("Attempting validation for %s %s %s\n", issuer, account, token)
			if err != nil {
				m := fmt.Sprintf("\nUnable to create OTP from bytes %s %v\n", token, err)
				log.Println(m)
				http.Error(w, m, http.StatusInternalServerError)
			} else {
				err = totp.Validate(token)
				if err != nil {
					m := fmt.Sprintf("\nFailed to validate token %s %v\n", token, err)
					log.Println(m)
					http.Error(w, m, http.StatusInternalServerError)
				} else {
					log.Println("Successfully validated code")
					w.Write([]byte("Successfully validated code"))
				}
			}
		} else {
			m := fmt.Sprintf("\nUser account %s not registered for issuer %s\n", account, issuer)
			log.Println(m)
			http.Error(w, m, http.StatusInternalServerError)
		}
	} else {
		m := fmt.Sprintf("\nIssuer not found %s\n", issuer)
		log.Println(m)
		http.Error(w, m, http.StatusInternalServerError)
	}
}

func run() {
	var jsonText []byte
	var err error
	if err = envflagstructconfig.Parse(&app); err != nil {
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

func main() {
	run()
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

	otp, err := twofactor.NewTOTP(account, issuer, crypto.SHA1, 6)
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

	// account is assumed to be an email
	if _, ok := issuerUserTOTP[issuer]; !ok {
		issuerUserTOTP[issuer] = make(UserMap)
	}

	if totpBytes, err := otp.ToBytes(); err == nil {
		issuerUserTOTP[issuer][account] = PngTotp{Png: qrBytes, Totp: totpBytes}

		if _, err = w.Write(qrBytes); err != nil {
			http.Error(w, "", http.StatusInternalServerError)
			return
		}
	} else {
		fmt.Println(err)
		log.Println(err)
	}
}
