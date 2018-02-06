package github

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

func TestUserGroups(t *testing.T) {

	orgs := []org{
		{Login: "org-1"},
		{Login: "org-2"},
		{Login: "org-3"},
	}

	teams := []team{
		{Name: "team-1", Org: org{Login: "org-1"}},
		{Name: "team-2", Org: org{Login: "org-1"}},
		{Name: "team-3", Org: org{Login: "org-1"}},
		{Name: "team-4", Org: org{Login: "org-2"}},
	}

	s := newTestServer(map[string]interface{}{
		"/user/orgs":  orgs,
		"/user/teams": teams,
	})

	connector := githubConnector{apiURL: s.URL}
	groups, err := connector.userGroups(context.Background(), &http.Client{})

	expectNil(t, err)
	expectEquals(t, groups, []string{
		"org-1:team-1",
		"org-1:team-2",
		"org-1:team-3",
		"org-2:team-4",
		"org-3",
	})

	s.Close()
}

func TestUserGroupsWithoutOrgs(t *testing.T) {

	s := newTestServer(map[string]interface{}{
		"/user/orgs":  []org{},
		"/user/teams": []team{},
	})

	connector := githubConnector{apiURL: s.URL}
	groups, err := connector.userGroups(context.Background(), &http.Client{})

	expectNil(t, err)
	expectEquals(t, len(groups), 0)

	s.Close()
}

func newTestServer(responses map[string]interface{}) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(responses[r.URL.Path])
	}))
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
