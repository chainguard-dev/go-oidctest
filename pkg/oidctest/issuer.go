/*
Copyright 2022 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package oidctest

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"gopkg.in/square/go-jose.v2"
)

// Stand up a very simple OIDC endpoint.
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
	var testIssuer *string

	oidcMux := http.NewServeMux()

	oidcMux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		t.Log("Handling request for openid-configuration.")
		if err := json.NewEncoder(w).Encode(struct {
			Issuer  string `json:"issuer"`
			JWKSURI string `json:"jwks_uri"`
		}{
			Issuer:  *testIssuer,
			JWKSURI: *testIssuer + "/keys",
		}); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})

	oidcMux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		t.Log("Handling request for jwks.")
		if err := json.NewEncoder(w).Encode(jose.JSONWebKeySet{
			Keys: []jose.JSONWebKey{
				jwk.Public(),
			},
		}); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})
	oidcServer := httptest.NewServer(oidcMux)
	t.Cleanup(oidcServer.Close)

	// Setup the testIssuer, so everything uses the right URL.
	testIssuer = &oidcServer.URL

	return signer, *testIssuer
}
