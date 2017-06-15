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
	if userTOTP, ok := issuerUserTOTP[issuer]; ok {
		if pngTotp, ok := userTOTP[account]; ok {
			totp, err := twofactor.TOTPFromBytes(pngTotp.Totp, issuer)
			log.Printf("Attempting validation for %s %s %s\n", issuer, account, token)
			if err != nil {
				status := fmt.Sprintf("Unable to create OTP from bytes %s %v", token, err)
				log.Println(status)
				WriteResult(account, issuer, token, status, w, http.StatusInternalServerError)
				return
			} else {
				err = totp.Validate(token)
				if err != nil {
					status := fmt.Sprintf("Fail %v token %s", err, token)
					log.Println(status)
					WriteResult(account, issuer, token, status, w, http.StatusInternalServerError)
					return
				} else {
					// log.Println("Successfully validated code")
					// w.Write([]byte("Successfully validated code"))
					status = "Successfully validated code"
					log.Println(status)
					WriteResult(account, issuer, token, status, w, http.StatusAccepted)
					return
				}
			}
		} else {
			status = fmt.Sprintf("User account %s not registered for issuer %s", account, issuer)
			log.Println(status)
			WriteResult(account, issuer, token, status, w, http.StatusInternalServerError)
			return
		}
	} else {
		status = fmt.Sprintf("Issuer not found %s", issuer)
		log.Println(status)
		WriteResult(account, issuer, token, status, w, http.StatusInternalServerError)
		return
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
