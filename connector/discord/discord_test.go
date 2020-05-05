package discord

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

type testResponse struct {
	data interface{}
}

func TestUserGuildsWithoutRoles(t *testing.T) {
	s := newTestServer(map[string]testResponse{
		"/users/@me/guilds": {
			data: []discordGuild{
				{
					ID:   "2",
					Name: "guild-2",
				},
				{
					ID:   "3",
					Name: "guild-3",
				},
			},
		},
	})

	defer s.Close()

	c := discordConnector{baseURL: s.URL}
	groups, err := c.userGuilds(context.Background(), newClient(), "1")

	expectNil(t, err)
	expectEquals(t, groups, []string{
		"guild-2",
		"guild-3",
	})
}

func TestUserGuildsWithRoles(t *testing.T) {
	s := newTestServer(map[string]testResponse{
		"/users/@me/guilds": {
			data: []discordGuild{
				{
					ID:   "2",
					Name: "guild-2",
				},
				{
					ID:   "3",
					Name: "guild-3",
				},
			},
		},
		"/guilds/2/roles": {
			data: []discordRole{
				{
					ID:   "4",
					Name: "role-4",
				},
				{
					ID:   "5",
					Name: "role-5",
				},
			},
		},
		"/guilds/2/members/1": {
			data: map[string]interface{}{
				"roles": []string{"4", "5"},
			},
		},
	})

	defer s.Close()

	c := discordConnector{baseURL: s.URL}
	groups, err := c.userGuilds(context.Background(), newClient(), "1")

	expectNil(t, err)
	expectEquals(t, groups, []string{
		"guild-2",
		"guild-2:role-4",
		"guild-2:role-5",
		"guild-3",
	})
}

func newTestServer(responses map[string]testResponse) *httptest.Server {
	var s *httptest.Server
	s = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := responses[r.RequestURI]
		w.Header().Add("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response.data)
	}))
	return s
}

func newClient() *http.Client {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	return &http.Client{Transport: tr}
}

func expectNil(t *testing.T, a interface{}) {
	if a != nil {
		t.Errorf("Expected %+v to equal nil", a)
	}
}

func expectEquals(t *testing.T, a interface{}, b interface{}) {
	if !reflect.DeepEqual(a, b) {
		t.Errorf("Expected %+v to equal %+v", a, b)
	}
}
