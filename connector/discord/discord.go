// Package discord provides authentication strategies using GitHub.
package discord

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"time"

	"golang.org/x/oauth2"

	"github.com/concourse/dex/connector"
	"github.com/concourse/dex/pkg/log"
)

const (
	baseURL = "https://discordapp.com/api"
	// Discord requires this scope to return email in user info
	scopeEmail = "email"
	// Discord requires this scope to return user info
	scopeIdentity = "identify"
	// Discord requires this scope to return basic information of user's guild
	scopeGuilds = "guilds"
)

// Config holds configuration options for discord logins.
type Config struct {
	ClientID           string   `json:"clientID"`
	ClientSecret       string   `json:"clientSecret"`
	RedirectURI        string   `json:"redirectURI"`
	RootCAs            []string `json:"rootCAs"`
	InsecureSkipVerify bool     `json:"insecureSkipVerify"`
}

type discordGuild struct {
	ID   string
	Name string
}

type discordRole struct {
	ID   string
	Name string
}

type discordUser struct {
	ID       string
	Username string
	Email    string
	Verified bool
}

// Open returns a strategy for logging in through Discord.
func (c *Config) Open(id string, logger log.Logger) (connector.Connector, error) {
	g := &discordConnector{
		redirectURI:  c.RedirectURI,
		clientID:     c.ClientID,
		clientSecret: c.ClientSecret,
		baseURL:      baseURL,
		logger:       logger,
	}

	return &g, nil
}

type discordConnector struct {
	redirectURI  string
	clientID     string
	clientSecret string
	baseURL      string
	logger       log.Logger
}

func (c *discordConnector) oauth2Config(scopes connector.Scopes) *oauth2.Config {
	discordScopes := []string{scopeIdentity, scopeEmail}
	if scopes.Groups {
		discordScopes = append(discordScopes, scopeGuilds)
	}

	discordEndpoints := oauth2.Endpoint{
		TokenURL: c.baseURL + "/oauth2/token",
		AuthURL:  c.baseURL + "/oauth2/authorize",
	}

	return &oauth2.Config{
		ClientID:     c.clientID,
		ClientSecret: c.clientSecret,
		Endpoint:     discordEndpoints,
		RedirectURL:  c.redirectURI,
		Scopes:       discordScopes,
	}
}

func (c *discordConnector) LoginURL(scopes connector.Scopes, callbackURL, state string) (string, error) {
	if c.redirectURI != callbackURL {
		return "", fmt.Errorf("expected callback URL %q did not match the URL in the config %q", callbackURL, c.redirectURI)
	}

	return c.oauth2Config(scopes).AuthCodeURL(state), nil
}

type oauth2Error struct {
	error            string
	errorDescription string
}

func (e *oauth2Error) Error() string {
	if e.errorDescription == "" {
		return e.error
	}
	return e.error + ": " + e.errorDescription
}

// newHTTPClient returns a new HTTP client that trusts the custom delcared rootCA cert.
func newHTTPClient(rootCAs []string, insecureSkipVerify bool) (*http.Client, error) {
	pool, err := x509.SystemCertPool()
	if err != nil {
		return nil, err
	}

	tlsConfig := tls.Config{RootCAs: pool, InsecureSkipVerify: insecureSkipVerify}
	for _, rootCA := range rootCAs {
		rootCABytes, err := ioutil.ReadFile(rootCA)
		if err != nil {
			return nil, fmt.Errorf("failed to read root-ca: %v", err)
		}
		if !tlsConfig.RootCAs.AppendCertsFromPEM(rootCABytes) {
			return nil, fmt.Errorf("no certs found in root CA file %q", rootCA)
		}
	}

	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tlsConfig,
			Proxy:           http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
				DualStack: true,
			}).DialContext,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}, nil
}

// user queries the Discord API for profile information using the provided client.
func (c *discordConnector) user(ctx context.Context, client *http.Client) (discordUser, error) {
	var u discordUser

	resp, err := client.Get(fmt.Sprintf("%s/users/@me", baseURL))
	if err != nil {
		return u, fmt.Errorf("discord: failed to execute request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return u, fmt.Errorf("discord: read body: %v", err)
		}
		return u, fmt.Errorf("%s: %s", resp.Status, body)
	}

	if err := json.NewDecoder(resp.Body).Decode(&u); err != nil {
		return u, fmt.Errorf("failed to decode response: %v", err)
	}

	return u, nil
}

func handleErrorResponse(resp *http.Response) error {
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("discord: read body: %v", err)
	}
	return fmt.Errorf("%s: %s", resp.Status, body)
}

// userGuilds queries the Discord API for user Guilds information.
// It returns a list of guilds and guild:role mapping as groups.
func (c *discordConnector) userGuilds(ctx context.Context, client *http.Client, userID string) ([]string, error) {
	var guildRoles []string

	resp, err := client.Get(fmt.Sprintf("%s/users/@me/guilds", c.baseURL))
	if err != nil {
		return nil, fmt.Errorf("discord: failed to execute request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, handleErrorResponse(resp)
	}

	var guilds []discordGuild

	if err := json.NewDecoder(resp.Body).Decode(&guilds); err != nil {
		return nil, fmt.Errorf("failed to decode response: %v", err)
	}

	for _, guild := range guilds {
		guildRoles = append(guildRoles, fmt.Sprintf("%s", guild.Name))

		roles, err := c.guildRoles(ctx, client, guild.ID)
		if err != nil {
			return guildRoles, fmt.Errorf("discord: get guild roles: %v", err)
		}

		var roleMap = make(map[string]string)
		for _, role := range roles {
			roleMap[role.ID] = role.Name
		}

		userRoleIDs, err := c.guildRoleIDs(ctx, client, guild.ID, userID)
		if err != nil {
			return nil, fmt.Errorf("discord: get user role IDs in guild: %v", err)
		}

		for _, roleID := range userRoleIDs {
			guildRoles = append(guildRoles, fmt.Sprintf("%s:%s", guild.Name, roleMap[roleID]))
		}
	}

	return guildRoles, nil
}

// guildRoles queries the Discord API for roles information of a guild
func (c *discordConnector) guildRoles(ctx context.Context, client *http.Client, guildID string) ([]discordRole, error) {

	resp, err := client.Get(fmt.Sprintf("%s/guilds/%s/roles", c.baseURL, guildID))
	if err != nil {
		return nil, fmt.Errorf("discord: failed to execute request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, handleErrorResponse(resp)
	}

	var roles []discordRole
	if err := json.NewDecoder(resp.Body).Decode(&roles); err != nil {
		return nil, fmt.Errorf("failed to decode response: %v", err)
	}

	return roles, nil
}

// guildRoleIDs queries Discord API for user's role information within a guild
func (c *discordConnector) guildRoleIDs(ctx context.Context, client *http.Client, guildID string, userID string) ([]string, error) {
	resp, err := client.Get(fmt.Sprintf("%s/guilds/%s/members/%s", c.baseURL, guildID, userID))
	if err != nil {
		return nil, fmt.Errorf("discord: new req: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, handleErrorResponse(resp)
	}

	var guildMember struct {
		RoleIDs []string `json:"roles"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&guildMember); err != nil {
		return nil, fmt.Errorf("failed to decode response: %v", err)
	}

	return guildMember.RoleIDs, nil
}

func (c *discordConnector) HandleCallback(s connector.Scopes, r *http.Request) (identity connector.Identity, err error) {
	q := r.URL.Query()
	if errType := q.Get("error"); errType != "" {
		return identity, &oauth2Error{errType, q.Get("error_description")}
	}

	oauth2Config := c.oauth2Config(s)

	ctx := r.Context()

	token, err := oauth2Config.Exchange(ctx, q.Get("code"))
	if err != nil {
		return identity, fmt.Errorf("discord: failed to get token: %v", err)
	}

	client := oauth2Config.Client(ctx, token)

	user, err := c.user(ctx, client)
	if err != nil {
		return identity, fmt.Errorf("Discord Connector: failed to execute request to user: %v", err)
	}

	identity = connector.Identity{
		UserID:        user.ID,
		Name:          user.Username,
		Username:      user.Username,
		Email:         user.Email,
		EmailVerified: user.Verified,
	}

	if s.Groups {
		groups, err := c.userGuilds(ctx, client, user.ID)
		if err != nil {
			return identity, fmt.Errorf("discord: get groups: %v", err)
		}
		identity.Groups = groups
	}

	return identity, nil
}
