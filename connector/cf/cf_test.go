package cf

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/coreos/dex/connector"
	"github.com/sirupsen/logrus"
)

type responseTest struct {
	serverURL string
}

type ApiInfo struct{}

func testSetup() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		token := "eyJhbGciOiJSUzI1NiIsImtpZCI6ImtleS0xIiwidHlwIjoiSldUIn0.eyJqdGkiOiIxMjk4MTNhZjJiNGM0ZDNhYmYyNjljMzM4OTFkZjNiZCIsInN1YiI6ImNmMWFlODk4LWQ1ODctNDBhYS1hNWRiLTE5ZTY3MjI0N2I1NyIsInNjb3BlIjpbImNsb3VkX2NvbnRyb2xsZXIucmVhZCIsIm9wZW5pZCJdLCJjbGllbnRfaWQiOiJjb25jb3Vyc2UiLCJjaWQiOiJjb25jb3Vyc2UiLCJhenAiOiJjb25jb3Vyc2UiLCJncmFudF90eXBlIjoiYXV0aG9yaXphdGlvbl9jb2RlIiwidXNlcl9pZCI6ImNmMWFlODk4LWQ1ODctNDBhYS1hNWRiLTE5ZTY3MjI0N2I1NyIsIm9yaWdpbiI6InVhYSIsInVzZXJfbmFtZSI6ImFkbWluIiwiZW1haWwiOiJhZG1pbiIsImF1dGhfdGltZSI6MTUyMzM3NDIwNCwicmV2X3NpZyI6IjYxNWJjMTk0IiwiaWF0IjoxNTIzMzc3MTUyLCJleHAiOjE1MjM0MjAzNTIsImlzcyI6Imh0dHBzOi8vdWFhLnN0eXgucHVzaC5nY3AuY2YtYXBwLmNvbS9vYXV0aC90b2tlbiIsInppZCI6InVhYSIsImF1ZCI6WyJjbG91ZF9jb250cm9sbGVyIiwiY29uY291cnNlIiwib3BlbmlkIl19.FslbnwvW0WScVRNK8IWghRX0buXfl6qaI1K7z_dzjPUVrdEyMtaYa3kJI8srA-2G1PjSSEWa_3Vzs_BEnTc3iG0JQWU0XlcjdCdAFTvnmKiHSzffy1O_oGYyH47KXtnZOxHf3rdV_Xgw4XTqPrfKXQxnPemUAJyKf2tjgs3XToGaqqBw-D_2BQVY79kF0_GgksQsViqq1GW0Dur6m2CgBhtc2h1AQGO16izXl3uNbpW6ClhaW43NQXlE4wqtr7kfmxyOigHJb2MSQ3wwPc6pqYdUT6ka_TMqavqbxEJ4QcS6SoEcVsDTmEQ4c8dmWUgXM0AZjd0CaEGTB6FDHxH5sw"
		w.Header().Add("Content-Type", "application/json")
		json.NewEncoder(w).Encode(&map[string]string{
			"access_token": token,
		})
	})

	mux.HandleFunc("/v2/info", func(w http.ResponseWriter, r *http.Request) {
		url := fmt.Sprintf("http://%s", r.Host)

		json.NewEncoder(w).Encode(&map[string]string{
			"token_endpoint": url,
		})
	})

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		url := fmt.Sprintf("http://%s", r.Host)

		json.NewEncoder(w).Encode(&map[string]string{
			"token_endpoint":         url,
			"authorization_endpoint": url,
			"userinfo_endpoint":      url,
		})
	})

	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
	})

	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(&map[string]string{
			"user_id":   "12345",
			"user_name": "test-user",
			"email":     "blah-email",
		})
	})

	mux.HandleFunc("/v2/users/", func(w http.ResponseWriter, r *http.Request) {
		var result *map[string]interface{}

		if strings.Contains(r.URL.String(), "spaces") {
			result = &map[string]interface{}{
				"resources": []map[string]interface{}{
					{
						"metadata": map[string]string{"guid": "some-space-guid"},
						"entity":   map[string]string{"name": "some-space-name", "organization_guid": "some-org-guid"},
					},
				},
			}
		}

		if strings.Contains(r.URL.String(), "organizations") {
			result = &map[string]interface{}{
				"resources": []map[string]interface{}{
					{
						"metadata": map[string]string{"guid": "some-org-guid"},
						"entity":   map[string]string{"name": "some-org-name"},
					},
					{
						"metadata": map[string]string{"guid": "some-org-guid-2"},
						"entity":   map[string]string{"name": "some-org-name-2"},
					},
				},
			}
		}
		json.NewEncoder(w).Encode(&result)
	})

	return httptest.NewServer(mux)
}

func (r responseTest) run(t *testing.T) {
	callBackURL := fmt.Sprintf("%s/callback", r.serverURL)

	c := Config{
		APIURL:             r.serverURL,
		ClientID:           "test-client",
		ClientSecret:       "secret",
		RedirectURI:        callBackURL,
		InsecureSkipVerify: true,
	}

	log := logrus.New()

	conn, err := c.Open("id", log)
	if err != nil {
		t.Fatal(err)
	}

	cfConn, ok := conn.(*cfConnector)
	if !ok {
		t.Fatal(errors.New("it is not cf conn "))
	}

	if cfConn.clientID != "test-client" {
		t.Fatal(errors.New("client ID  is not matching"))
	}
	if cfConn.clientSecret != "secret" {
		t.Fatal(errors.New("client secret is not matching"))
	}
	if cfConn.redirectURI != callBackURL {
		t.Fatal(errors.New(fmt.Sprintf("client redirect URI is not matching got %s expected %s", cfConn.redirectURI, callBackURL)))
	}

}

func TestGoodResponse(t *testing.T) {
	testServer := testSetup()
	defer testServer.Close()

	test := responseTest{
		serverURL: testServer.URL}

	test.run(t)
}

func TestHandleCallback(t *testing.T) {

	testServer := testSetup()
	defer testServer.Close()

	cfConn := &cfConnector{
		tokenURL:         fmt.Sprintf("%s/token", testServer.URL),
		authorizationURL: fmt.Sprintf("%s/authorize", testServer.URL),
		userinfoURL:      fmt.Sprintf("%s/userinfo", testServer.URL),
		apiURL:           testServer.URL,
		clientSecret:     "secret",
		clientID:         "test-client",
		redirectURI:      "localhost:8080/sky/dex/callback",
		httpClient:       http.DefaultClient,
	}

	req, err := http.NewRequest("GET", testServer.URL, nil)
	if err != nil {
		t.Fatal("failed to create request", err)
	}

	t.Run("CallbackWithScopes", func(t *testing.T) {
		identity, err := cfConn.HandleCallback(connector.Scopes{Groups: true}, req)
		if err != nil {
			t.Fatalf("Call back failed", err)
		}

		if len(identity.Groups) == 1 {
			t.Fatal("groups not populated")
		}

		if identity.Groups[0] != "some-org-name:some-space-name" {
			t.Fatal("groups with org-name:space-name did not match; recieved ", identity.Groups[0])
		}
		if identity.Groups[1] != "some-org-name-2" {
			t.Fatal("groups with only org name did not match; recieved ", identity.Groups[1])
		}
	})

	t.Run("CallbackWithoutScopes", func(t *testing.T) {
		identity, err := cfConn.HandleCallback(connector.Scopes{}, req)
		if err != nil {
			t.Fatalf("Handle callback failed with error", err)
		}
		if identity.UserID != "12345" {
			t.Fatal("user id isnt matching; expected %s got %s", "12345", identity.UserID)
		}
		if identity.Username != "test-user" {
			t.Fatal("user name isnt matching; expected %s got %s", "test-user", identity.Username)
		}
	})

	t.Run("CallbackWithOfflineAccess", func(t *testing.T) {
		identity, err := cfConn.HandleCallback(connector.Scopes{OfflineAccess: true}, req)

		if err != nil {
			t.Fatalf("Call back failed", err)
		}

		if len(identity.ConnectorData) <= 0 {
			t.Fatal("Missinng connector data for offline access")
		}
		cData := connectorData{}
		err = json.Unmarshal(identity.ConnectorData, &cData)

		if err != nil {
			t.Fatalf("Json Unmarshal err", err)
		}

		if cData.AccessToken == "" {
			t.Fatal("Missinng access token for offline access")
		}
	})
}
