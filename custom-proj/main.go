package main

import (
	"fmt"
	"github.com/coreos/go-oidc"
	"github.com/google/uuid"
	"golang.org/x/oauth2"
	"html/template"
	"log"
	"net/http"
	"time"
)

const (
	baseUrl            = "http://127.0.0.1:8080"
	signInPath         = "/sign-in"
	signInCallbackPath = "/callback"
)

type WelcomePageData struct {
	Title   string
	AuthURL string
}

type DashboardPageData struct {
	IsLoggedIn bool
}

type Token struct {
	// AccessToken is the token that authorizes and authenticates
	// the requests.
	AccessToken string `json:"access_token"`

	// TokenType is the type of token.
	// The Type method returns either this or "Bearer", the default.
	TokenType string `json:"token_type,omitempty"`

	// RefreshToken is a token that's used by the application
	// (as opposed to the user) to refresh the access token
	// if it expires.
	RefreshToken string `json:"refresh_token,omitempty"`

	// Expiry is the optional expiration time of the access token.
	//
	// If zero, TokenSource implementations will reuse the same
	// token forever and RefreshToken or equivalent
	// mechanisms for that TokenSource will not be used.
	Expiry time.Time `json:"expiry,omitempty"`

	// IDToken is the OpenID addition to the excellent OAuth 2.0
	IDToken string `json:"id_token,omitempty"`
}

func main() {
	// public page
	http.HandleFunc("/", WelcomeHandler)

	// protected pages
	http.HandleFunc("/dashboard", DashboardHandler)

	// redirection pages
	http.HandleFunc(signInPath, SignInHandler)
	http.HandleFunc(signInCallbackPath, SignInCallbackHandler)

	fmt.Println("Server is running on http://127.0.0.1:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func WelcomeHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	oidcCookie, err := GetAuthCookie(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if len(oidcCookie) > 0 {
		http.Redirect(w, r, baseUrl+"/dashboard", http.StatusFound)
		return
	}

	tmpl, err := template.ParseFiles("templates/welcome.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	data := WelcomePageData{
		Title:   "Welcome",
		AuthURL: baseUrl + signInPath,
	}

	err = tmpl.Execute(w, data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func DashboardHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	oidcCookie, err := GetAuthCookie(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	data := DashboardPageData{
		IsLoggedIn: len(oidcCookie) > 0,
	}

	tmpl, err := template.ParseFiles("templates/dashboard.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	err = tmpl.Execute(w, data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func SignInHandler(w http.ResponseWriter, r *http.Request) {
	state := uuid.New().String()

	if err := encryptTempToCookie(w, r, "state", state, "/"); err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	url := "http://127.0.0.1:4444/oauth2/auth?client_id=3a106ced-2643-4c33-9c3c-a51595eb2cc0&redirect_uri=http%3A%2F%2F127.0.0.1%3A8080%2Fcallback&response_type=code&state=" + state + "&scope=offline%20openid"

	http.Redirect(w, r, url, http.StatusFound)
}

func SignInCallbackHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	recState := r.URL.Query().Get("state")

	state, err := decryptTempFromCookie(w, r, "state")
	if err != nil {
		if err == http.ErrNoCookie {
			http.Error(w, "State cookie not found", http.StatusBadRequest)
			return
		}

		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	if state != recState {
		http.Error(w, "State does not match", http.StatusBadRequest)
		return
	}

	code := r.URL.Query().Get("code")

	authConfig := oauth2.Config{
		Endpoint: oauth2.Endpoint{
			TokenURL: "http://127.0.0.1:4444/oauth2/token",
		},
		ClientID: "3a106ced-2643-4c33-9c3c-a51595eb2cc0",
		Scopes:   []string{oidc.ScopeOpenID, "profile offline"},
	}

	oauth2Token, err := authConfig.Exchange(
		r.Context(),
		code,
		oauth2.SetAuthURLParam("redirect_uri", fmt.Sprintf("http://%s%s", r.Host, signInCallbackPath)),
	)
	if err != nil {
		fmt.Println(err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		fmt.Println("No id_token field in oauth2 token.")
		http.Redirect(w, r, baseUrl, http.StatusFound)
		return
	}

	if err = SetAuthCookie(w, r, &Token{
		IDToken:      rawIDToken,
		AccessToken:  oauth2Token.AccessToken,
		Expiry:       oauth2Token.Expiry,
		RefreshToken: oauth2Token.RefreshToken,
		TokenType:    oauth2Token.TokenType,
	}); err != nil {
		fmt.Println(err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, baseUrl+"/dashboard", http.StatusFound)
}
