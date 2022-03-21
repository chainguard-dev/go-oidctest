/*
Copyright 2022 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package oidctest_test

import (
	"context"
	"testing"
	"time"

	"chainguard.dev/go-oidctest/pkg/oidctest"
	"github.com/coreos/go-oidc/v3/oidc"
	"gopkg.in/square/go-jose.v2/jwt"
)

func TestNewIssuer(t *testing.T) {
	ctx := context.Background()

	signer, iss := oidctest.NewIssuer(t)

	token, err := jwt.Signed(signer).Claims(jwt.Claims{
		Issuer:   iss,
		IssuedAt: jwt.NewNumericDate(time.Now()),
		Expiry:   jwt.NewNumericDate(time.Now().Add(30 * time.Minute)),
		Subject:  "test-subject",
		Audience: jwt.Audience{"test-audience"},
	}).CompactSerialize()
	if err != nil {
		t.Fatalf("CompactSerialize() = %v", err)
	}

	// Verify the token is valid.
	provider, err := oidc.NewProvider(ctx, iss)
	if err != nil {
		t.Errorf("constructing %q provider: %v", iss, err)
	}

	verifier := provider.Verifier(&oidc.Config{SkipClientIDCheck: true})
	if _, err := verifier.Verify(ctx, token); err != nil {
		t.Errorf("verifying token: %v", err)
	}
}
