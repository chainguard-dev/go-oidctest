# go-oidc-test
Library for creating fake OIDC issuers in tests.

## Test issuer

`oidctest.NewIssuer` creates a fake OIDC issuer. It returns its signing key as
well as its issuer URL.

Example:

```go
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
```
