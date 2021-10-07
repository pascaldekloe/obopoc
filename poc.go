// Package main provides a proof-of-concept command, which validates the entire
// on-behalf-of flow on Kusto.
package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
)

// Scopes are case-sensitive tokens, separated by space, in arbitrary order.
const scopes = "openid profile"

// Report receives a trace log.
var Report *log.Logger

func main() {
	// The Azure setup is defined as constants here for convenience. See the
	// “App Registrations” page from the portal <https://portal.azure.com/>
	// for your actual values.
	const (
		// DirectoryID is a tenant identifier, assigned by Azure.
		DirectoryID = "9a2ddabe-90c0-4e09-bf28-a91111a56ed7"
		// ApplicationID is an identifier, assigned by Azure.
		ApplicationID = "9297b92b-c28c-4fd6-a018-65ea880ca470"

		// RedirectURL is the return destination configured for logins.
		RedirectURL = "https://example.com/poc"
	)

	// The Azure Data Explorer (a.k.a. ADX) selection must be configured
	// with “user impersonation” permissions. See README.md for details.
	const (
		ClusterURL   = "https://obopocdata.westeurope.kusto.windows.net"
		DatabaseName = "obopocdb"
	)

	log.SetFlags(0)

	var applicationSecret string // credential for the service principal
	if bytes, err := os.ReadFile("app-secret.txt"); err != nil {
		log.Fatal("application credential unavailable: ", err)
	} else {
		applicationSecret = strings.TrimSpace(string(bytes))
	}

	f, err := os.Create("report.txt")
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	Report = log.New(f, "", log.LstdFlags)

	config, err := OpenIDConfigLookup(DirectoryID)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("got Azure locations %#v", config)

	authCode, err := authCodeDialog(config, ClusterURL, ApplicationID, RedirectURL)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("got authorization code %q", authCode)

	clientToken, err := AccessTokenAcquire(config, ApplicationID, applicationSecret, RedirectURL, authCode)
	if err != nil {
		log.Fatal("client token unavailable: ", err)
	}
	Report.Print("client token claims: ", tokenClaims(clientToken))
	log.Printf("got client token %q", clientToken)

	onBehalfToken, err := AccessTokenSwap(config, ClusterURL, ApplicationID, applicationSecret, clientToken)
	if err != nil {
		log.Fatal("on-behalf token unavailable: ", err)
	}
	Report.Print("on-behalf token claims: ", tokenClaims(onBehalfToken))
	log.Printf("got on-behalf token %q", onBehalfToken)

	err = kustoPoke(onBehalfToken, ClusterURL, DatabaseName)
	if err != nil {
		log.Fatal(err)
	}
	log.Print("POC complete ✓")
}

// OpenIDConfig is a selection of configuration parameters. See
// <https://openid.net/specs/openid-connect-discovery-1_0.html>
// for the full specification.
type OpenIDConfig struct {
	TokenURL string `json:"token_endpoint"`
	AuthURL  string `json:"authorization_endpoint"`
}

// OpenIDConfigLookup resolves the configuration for a directory [tenant].
func OpenIDConfigLookup(directoryID string) (*OpenIDConfig, error) {
	// HTTP Resolve
	url := "https://login.microsoftonline.com/" + url.PathEscape(directoryID) + "/v2.0/.well-known/openid-configuration"
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("OpenID configuration lookup: %w", err)
	}
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("GET %s status %q", url, resp.Status)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("GET %s response: %w", url, err)
	}
	Report.Printf("OpenID configuration <%s>: %s", url, indentJSON(body))

	// Parse Essentials
	var c OpenIDConfig
	if err := json.Unmarshal(body, &c); err != nil {
		return nil, fmt.Errorf("received malformed OpenID configuration: %w", err)
	}
	return &c, nil
}

// AuthCodeURL composes the destination for an interactive login.
func AuthCodeURL(c *OpenIDConfig, targetURL, applicationID, redirectURL string) string {
	q := "response_type=code"
	q += "&redirect_uri=" + url.QueryEscape(redirectURL)
	q += "&response_mode=query"
	q += "&scope=" + url.QueryEscape(scopes+" "+targetURL+"/.default")
	q += "&client_id=" + applicationID

	if strings.ContainsRune(c.AuthURL, '?') {
		return c.AuthURL + "&" + q
	} else {
		return c.AuthURL + "?" + q
	}
}

// AuthCodeDialog resolves an authorization code for the client.
func authCodeDialog(c *OpenIDConfig, targetURL, applicationID, redirectURL string) (authCode string, err error) {
	fmt.Printf("login at %s…\n", AuthCodeURL(c, targetURL, applicationID, redirectURL))
	fmt.Printf("enter the redirect URL (at %s): ", redirectURL)
	in, _, err := bufio.NewReader(os.Stdin).ReadLine()
	if err != nil {
		return "", err
	}

	u, err := url.Parse(string(in))
	if err != nil {
		return "", fmt.Errorf("malformed redirect URL %q: %w", in, err)
	}
	authCode = u.Query().Get("code")
	if authCode == "" {
		return "", fmt.Errorf(`query-parameter "code" absent in redirect URL %q`, in)
	}
	return authCode, nil
}

// AccessTokenAquire uses an authorization code.
func AccessTokenAcquire(c *OpenIDConfig, applicationID, applicationSecret, redirectURL, authCode string) (token string, err error) {
	// Collect Attributes
	params := make(url.Values)
	params.Set("client_id", applicationID)
	params.Set("client_secret", applicationSecret)
	params.Set("grant_type", "authorization_code")
	params.Set("code", authCode)
	params.Set("redirect_uri", redirectURL)
	// MitM protection [code_verifier] omited for proof of concept.

	// HTTP Exchange
	resp, err := http.PostForm(c.TokenURL, params)
	if err != nil {
		return "", fmt.Errorf("authorization-code grant exchange: %w", err)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("authorization-code grant POST <%q> response: %w", c.TokenURL, err)
	}
	Report.Printf("authorization-code grant (HTTP %q) response: %s", resp.Status, indentJSON(body))

	if resp.StatusCode/100 != 2 {
		return "", fmt.Errorf("authorization-code grant POST <%q> status %q", c.TokenURL, resp.Status)
	}

	// Parse Essentials
	var r struct {
		Token string `json:"id_token"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		return "", fmt.Errorf("received malformed authorization-code grant: %w", err)
	}
	return r.Token, nil
}

// AccessTokenSwap resolves an on-behalf-of token.
func AccessTokenSwap(c *OpenIDConfig, targetURL, applicationID, applicationSecret, accessToken string) (string, error) {
	// Collect Attributes
	params := make(url.Values)
	params.Set("client_id", applicationID)
	params.Set("client_secret", applicationSecret)
	params.Set("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer")
	params.Set("assertion", accessToken)
	params.Set("scope", targetURL+"/.default")
	params.Set("requested_token_use", "on_behalf_of")

	// HTTP Exchange
	resp, err := http.PostForm(c.TokenURL, params)
	if err != nil {
		return "", fmt.Errorf("token-swap POST <%q>: %w", c.TokenURL, err)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("token-swap POST <%q> response: %w", c.TokenURL, err)
	}
	Report.Printf("token-swap <%q> response: %s", c.TokenURL, indentJSON(body))
	if resp.StatusCode/100 != 2 {
		return "", fmt.Errorf("token-swap POST <%q> status %q", c.TokenURL, resp.Status)
	}

	// Parse Essentials
	var r struct {
		Token string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		return "", fmt.Errorf("malformed token-swap response: %w", err)
	}
	return r.Token, nil
}

// KustoPoke exectues an arbitrary query with the token credentials.
func kustoPoke(token, targetURL, databaseName string) error {
	query := fmt.Sprintf(`{"db": %q, "csl": "print Test=\"Hello World!\""}"`, databaseName)
	queryURL := targetURL + "/v2/rest/query"
	req, err := http.NewRequest("POST", queryURL, strings.NewReader(query))
	if err != nil {
		log.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	req.Header.Set("Authorization", "bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("kusto unavailable: %w", err)
	}
	Report.Printf("got Kusto HTTP %q", resp.Status)

	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("kusto gave HTTP %q", resp.Status)
	}
	return nil
}

// IndentJSON formats the text on best-effort basis.
func indentJSON(text []byte) string {
	var buf bytes.Buffer
	err := json.Indent(&buf, text, "> ", "\t")
	if err != nil {
		return "⸌malformed JSON⸍ " + strconv.Quote(string(text))
	}
	return buf.String()
}

// TokenClaims extracts the claims, and it formats the JSON, all on best-effort
// basis.
func tokenClaims(token string) string {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "⸌malformed JWT⸍"
	}
	claims, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "⸌malformed JWT encoding⸍"
	}
	return indentJSON(claims)
}
