/*
Copyright 2022 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package oidctest

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// Stand up a simple OIDC endpoint.
func NewIssuer(t *testing.T) (jose.Signer, string) {
	t.Helper()

	pk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("cannot generate RSA key %v", err)
	}
	jwk := jose.JSONWebKey{
		Algorithm: string(jose.RS256),
		Key:       pk,
	}
	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.RS256,
		Key:       jwk.Key,
	}, nil)
	if err != nil {
		t.Fatalf("jose.NewSigner() = %v", err)
	}

	// Populated below, but we need to capture it first.
	oidcMux := http.NewServeMux()
	oidcServer := httptest.NewServer(oidcMux)
	testIssuer := oidcServer.URL

	oidcMux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		t.Log("Handling request for openid-configuration.")
		if err := json.NewEncoder(w).Encode(struct {
			Issuer        string `json:"issuer"`
			JWKSURI       string `json:"jwks_uri"`
			AuthzEndpoint string `json:"authorization_endpoint"`
			TokenEndpoint string `json:"token_endpoint"`
		}{
			Issuer:        testIssuer,
			JWKSURI:       testIssuer + "/keys",
			AuthzEndpoint: testIssuer + "/authz",
			TokenEndpoint: testIssuer + "/token",
		}); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	})

	oidcMux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		t.Log("Handling request for jwks.")
		w.Header().Add("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(jose.JSONWebKeySet{
			Keys: []jose.JSONWebKey{
				jwk.Public(),
			},
		}); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	})

	// code stores information sent inside the `code` OAuth parameter.
	type code struct {
		ClientID string `json:"client_id"`
		Nonce    string `json:"nonce"`
	}

	oidcMux.HandleFunc("/authz", func(w http.ResponseWriter, r *http.Request) {
		t.Log("Handling request for authz.")
		redirectURL, err := url.Parse(r.URL.Query().Get("redirect_uri"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Rely on `code` as a mechanism to encode information required by the token
		// endpoint.
		c, err := json.Marshal(code{
			ClientID: r.URL.Query().Get("client_id"),
			Nonce:    r.URL.Query().Get("nonce"),
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		v := url.Values{
			"state": {r.URL.Query().Get("state")},
			"code":  {base64.StdEncoding.EncodeToString(c)},
		}
		redirectURL.RawQuery = v.Encode()

		http.Redirect(w, r, redirectURL.String(), http.StatusFound)
	})

	oidcMux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		t.Log("Handling request for token.")

		rawCode, err := base64.StdEncoding.DecodeString(r.FormValue("code"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		var c code
		if err := json.Unmarshal(rawCode, &c); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		token, err := jwt.Signed(signer).Claims(struct {
			jwt.Claims `json:",inline"` // nolint:revive // unknown option 'inline' in JSON tag

			Nonce string `json:"nonce"`
		}{
			Claims: jwt.Claims{
				Issuer:   testIssuer,
				IssuedAt: jwt.NewNumericDate(time.Now()),
				Expiry:   jwt.NewNumericDate(time.Now().Add(30 * time.Minute)),
				Subject:  "test-subject",
				Audience: jwt.Audience{c.ClientID},
			},
			Nonce: c.Nonce,
		}).Serialize()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Add("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(struct {
			IdToken     string `json:"id_token"`
			TokenType   string `json:"token_type"`
			AccessToken string `json:"access_token"`
		}{
			IdToken:     token,
			TokenType:   "Bearer",
			AccessToken: "garbage",
		}); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	})

	t.Cleanup(oidcServer.Close)

	return signer, testIssuer
}
