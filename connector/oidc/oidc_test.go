package oidc

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coreos/dex/connector"
	"github.com/sirupsen/logrus"
	"gopkg.in/square/go-jose.v2"
)

func TestOpen(t *testing.T) {
	testServer := testSetup(t)
	defer testServer.Close()

	testConfig := Config{
		Issuer:        testServer.URL,
		ClientID:      "testClient",
		ClientSecret:  "secret",
		Scopes:        []string{"groups"},
		RedirectURI:   "testURL",
		HostedDomains: []string{"http://hosteddomain.com"},
	}
	log := logrus.New()

	conn, err := testConfig.Open("id", log)
	if err != nil {
		t.Fatal(err)
	}

	oidcConn, ok := conn.(*oidcConnector)
	if !ok {
		t.Fatal(errors.New("it is not oidc conn "))
	}

	if oidcConn.oauth2Config.ClientID != "testClient" {
		t.Fatal(errors.New("client id does not match"))
	}

	if oidcConn.oauth2Config.ClientSecret != "secret" {
		t.Fatal(errors.New("client secret does not match"))
	}

	if oidcConn.hostedDomains[0] != "http://hosteddomain.com" {
		t.Fatal(errors.New("hosted domain does not match"))
	}

	if oidcConn.oauth2Config.RedirectURL != "testURL" {
		t.Fatal(errors.New("redirect URL does not match"))
	}

	if oidcConn.oauth2Config.Endpoint.TokenURL != testServer.URL+"/token" {
		t.Fatal(errors.New("Token URL does not match"))
	}

	if oidcConn.oauth2Config.Endpoint.AuthURL != testServer.URL+"/authorize" {
		t.Fatal(errors.New("Authorize URL does not match"))
	}

	if len(oidcConn.oauth2Config.Scopes) != 2 {
		t.Fatal(errors.New("scopes are not of length 2"))
	}

	if oidcConn.oauth2Config.Scopes[0] != "openid" {
		t.Fatal(errors.New("scopes does not match"))
	}

	if oidcConn.oauth2Config.Scopes[1] != "groups" {
		t.Fatal(errors.New("scopes does not match"))
	}
}

func TestHandleCallBack(t *testing.T) {
	testServer := testSetup(t)
	defer testServer.Close()

	testConfig := Config{
		Issuer:       testServer.URL,
		ClientID:     "testClient",
		ClientSecret: "secret",
		Scopes:       []string{"groups"},
		RedirectURI:  "testURL",
		GroupsKey:    "groups_key",
	}
	log := logrus.New()

	conn, err := testConfig.Open("id", log)
	if err != nil {
		t.Fatal("failed to create oidc conn", err)
	}

	oidcConn, ok := conn.(*oidcConnector)
	if !ok {
		t.Fatal(errors.New("it is not oidc conn "))
	}

	req, err := http.NewRequest("GET", testServer.URL, nil)
	if err != nil {
		t.Fatal("failed to create request", err)
	}

	t.Run("HandleCalltoTokenEndpoint", func(t *testing.T) {
		values := req.URL.Query()
		values.Add("code", "some-code")
		req.URL.RawQuery = values.Encode()

		identity, err := oidcConn.HandleCallback(connector.Scopes{Groups: true}, req)
		if err != nil {
			t.Fatal("handle callback failed", err)
		}
		if len(identity.Groups) == 0 {
			t.Fatal("identity groups are not populated")
		}

		if identity.Groups[0] != "test-group" {
			t.Fatalf("identity group is %s but expected %s ", identity.Groups[0], "test-group")
		}

		if identity.Name != "test-name" {
			t.Fatalf("identity name is %s but expected %s", identity.Name, "test-name")
		}

		if identity.Username != "test-username" {
			t.Fatalf("identity name is %s but expected %s", identity.Username, "test-username")
		}

		if identity.Email != "test-email" {
			t.Fatalf("identity email is %s but expected %s", identity.Email, "test-email")
		}

		if !identity.EmailVerified {
			t.Fatal("identity email verified is expected to be true")
		}
	})
}

func TestKnownBrokenAuthHeaderProvider(t *testing.T) {
	tests := []struct {
		issuerURL string
		expect    bool
	}{
		{"https://dev.oktapreview.com", true},
		{"https://dev.okta.com", true},
		{"https://okta.com", true},
		{"https://dev.oktaaccounts.com", false},
		{"https://accounts.google.com", false},
	}

	for _, tc := range tests {
		got := knownBrokenAuthHeaderProvider(tc.issuerURL)
		if got != tc.expect {
			t.Errorf("knownBrokenAuthHeaderProvider(%q), want=%t, got=%t", tc.issuerURL, tc.expect, got)
		}
	}
}

func testSetup(t *testing.T) *httptest.Server {

	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal("Failed to generate rsa key", err)
	}

	jwk := jose.JSONWebKey{
		Key:       key,
		KeyID:     "some-key",
		Algorithm: "RSA",
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(&map[string]interface{}{
			"keys": []map[string]interface{}{{
				"alg": jwk.Algorithm,
				"kty": jwk.Algorithm,
				"kid": jwk.KeyID,
				"n":   n(&key.PublicKey),
				"e":   e(&key.PublicKey),
			}},
		})
	})

	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		url := fmt.Sprintf("http://%s", r.Host)

		token, err := newToken(&jwk, map[string]interface{}{
			"iss":            url,
			"aud":            "testClient",
			"exp":            time.Now().Add(time.Hour).Unix(),
			"groups_key":     []string{"test-group"},
			"name":           "test-name",
			"username":       "test-username",
			"email":          "test-email",
			"email_verified": true,
		})
		if err != nil {
			t.Fatal("unable to generate token", err)
		}

		w.Header().Add("Content-Type", "application/json")
		json.NewEncoder(w).Encode(&map[string]string{
			"access_token": token,
			"id_token":     token,
			"token_type":   "Bearer",
		})
	})

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		url := fmt.Sprintf("http://%s", r.Host)

		json.NewEncoder(w).Encode(&map[string]string{
			"issuer":                 url,
			"token_endpoint":         url + "/token",
			"authorization_endpoint": url + "/authorize",
			"userinfo_endpoint":      url + "/userinfo",
			"jwks_uri":               url + "/keys",
		})
	})
	return httptest.NewServer(mux)
}

func newToken(key *jose.JSONWebKey, claims map[string]interface{}) (string, error) {
	signingKey := jose.SigningKey{Key: key, Algorithm: jose.RS256}

	signer, err := jose.NewSigner(signingKey, &jose.SignerOptions{})
	if err != nil {
		return "", fmt.Errorf("new signer: %v", err)
	}

	payload, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("marshaling claims: %v", err)
	}

	signature, err := signer.Sign(payload)
	if err != nil {
		return "", fmt.Errorf("signing payload: %v", err)
	}
	return signature.CompactSerialize()
}

func n(pub *rsa.PublicKey) string {
	return encode(pub.N.Bytes())
}

func e(pub *rsa.PublicKey) string {
	data := make([]byte, 8)
	binary.BigEndian.PutUint64(data, uint64(pub.E))
	return encode(bytes.TrimLeft(data, "\x00"))
}

func encode(payload []byte) string {
	result := base64.URLEncoding.EncodeToString(payload)
	return strings.TrimRight(result, "=")
}
