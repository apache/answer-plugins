/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package vds

import (
	"context"
	"embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/mike-brown8/answer-connector-furtv/connector-vds/i18n"
	"github.com/apache/answer-plugins/util"
	"github.com/apache/answer/plugin"
	"github.com/segmentfault/pacman/log"
	"github.com/tidwall/gjson"
	"golang.org/x/oauth2"
)

var (
	//go:embed info.yaml
	Info embed.FS
	//go:embed assets/EMlogo-large1x.png
	logoAssets embed.FS
)

type Connector struct {
	Config            *ConnectorConfig
	platformSignature string
	signatureExpiry   time.Time
	logoDataURI       string // cached logo data URI
	mu                sync.RWMutex
}

// ConnectorConfig holds VDS-specific OAuth configuration.
// Only ClientID and ClientSecret need to be configured by users.
// PlatformSignature and logo are managed internally.
type ConnectorConfig struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

func init() {
	plugin.Register(&Connector{
		Config: &ConnectorConfig{},
	})
}

func (g *Connector) Info() plugin.Info {
	info := &util.Info{}
	info.GetInfo(Info)

	return plugin.Info{
		Name:        plugin.MakeTranslator(i18n.InfoName),
		SlugName:    info.SlugName,
		Description: plugin.MakeTranslator(i18n.InfoDescription),
		Author:      info.Author,
		Version:     info.Version,
		Link:        info.Link,
	}
}

func (g *Connector) ConnectorLogoSVG() string {
	return g.getLogoDataURICached()
}

func (g *Connector) ConnectorName() plugin.Translator {
	return plugin.MakeTranslator(i18n.ConnectorName)
}

func (g *Connector) ConnectorSlugName() string {
	return "vds"
}

func (g *Connector) ConnectorSender(ctx *plugin.GinContext, receiverURL string) (redirectURL string) {
	oauth2Config := &oauth2.Config{
		ClientID:     g.Config.ClientID,
		ClientSecret: g.Config.ClientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:  AuthorizeURL,
			TokenURL: TokenURL,
		},
		RedirectURL: receiverURL,
		Scopes:      strings.Split(DefaultScope, ","),
	}
	state := randomString(24)
	return oauth2Config.AuthCodeURL(state)
}

func (g *Connector) ConnectorReceiver(ctx *plugin.GinContext, receiverURL string) (userInfo plugin.ExternalLoginUserInfo, err error) {
	code := ctx.Query("code")
	if len(code) == 0 {
		return userInfo, fmt.Errorf("missing authorization code")
	}

	// Exchange authorization code for access token
	token, err := g.exchangeCodeForToken(code, receiverURL)
	if err != nil {
		return userInfo, err
	}

	// Fetch user information from VDS
	userInfo, err = g.getUserInfo(token.AccessToken)
	if err != nil {
		return userInfo, err
	}

	userInfo = g.formatUserInfo(userInfo)
	return userInfo, nil
}

// exchangeCodeForToken exchanges authorization code for access token with VDS.
func (g *Connector) exchangeCodeForToken(code, receiverURL string) (*oauth2.Token, error) {
	// Get platform signature for authenticating the token exchange request
	platformSig, err := g.getPlatformSignature()
	if err != nil {
		return nil, fmt.Errorf("failed to get platform signature: %w", err)
	}

	oauth2Config := &oauth2.Config{
		ClientID:     g.Config.ClientID,
		ClientSecret: g.Config.ClientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:   AuthorizeURL,
			TokenURL:  TokenURL,
			AuthStyle: oauth2.AuthStyleAutoDetect,
		},
		RedirectURL: receiverURL,
	}

	// Use custom transport to add platform signature to token exchange requests
	httpClient := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &vdsTransport{
			platformSignature: platformSig,
			base:              http.DefaultTransport,
		},
	}

	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, httpClient)
	token, err := oauth2Config.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("code exchange failed: %w", err)
	}

	return token, nil
}

// getUserInfo fetches user information from VDS API.
func (g *Connector) getUserInfo(accessToken string) (plugin.ExternalLoginUserInfo, error) {
	userInfo := plugin.ExternalLoginUserInfo{}

	// Get fresh platform signature for user info request
	platformSig, err := g.getPlatformSignature()
	if err != nil {
		return userInfo, fmt.Errorf("failed to get platform signature: %w", err)
	}

	req, err := http.NewRequest("GET", UserInfoURL, nil)
	if err != nil {
		return userInfo, fmt.Errorf("failed to create userinfo request: %w", err)
	}

	// Set required headers for VDS API
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", platformSig))
	req.Header.Set("X-OAuth-Access-Token", accessToken)

	client := &http.Client{Timeout: 15 * time.Second}
	response, err := client.Do(req)
	if err != nil {
		return userInfo, fmt.Errorf("failed to fetch user info: %w", err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(response.Body)
		return userInfo, fmt.Errorf("userinfo request failed with status %d: %s", response.StatusCode, string(body))
	}

	data, err := io.ReadAll(response.Body)
	if err != nil {
		return userInfo, fmt.Errorf("failed to read response body: %w", err)
	}

	userInfo.MetaInfo = string(data)

	// Extract user info using hardcoded JSON paths
	userInfo.ExternalID = gjson.GetBytes(data, UserIDPath).String()
	if len(userInfo.ExternalID) == 0 {
		log.Warnf("failed to extract user ID from VDS response")
		return userInfo, nil
	}

	userInfo.DisplayName = gjson.GetBytes(data, UserDisplayNamePath).String()
	userInfo.Username = gjson.GetBytes(data, UserUsernamePath).String()
	userInfo.Email = gjson.GetBytes(data, UserEmailPath).String()
	userInfo.Avatar = gjson.GetBytes(data, UserAvatarPath).String()

	return userInfo, nil
}

func (g *Connector) formatUserInfo(userInfo plugin.ExternalLoginUserInfo) plugin.ExternalLoginUserInfo {
	if len(userInfo.Username) == 0 {
		userInfo.Username = userInfo.ExternalID
	}

	// Normalize username: replace invalid characters with underscore
	username := userInfo.Username
	for i, r := range username {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' || r == '_' || r == '-') {
			username = string([]rune(username[:i])) + "_" + string([]rune(username[i+1:]))
		}
	}

	// Ensure username length is within valid range (4-30 characters)
	usernameLength := utf8.RuneCountInString(username)
	if usernameLength < MinUsernameLength {
		username = username + strings.Repeat("_", MinUsernameLength-usernameLength)
	} else if usernameLength > MaxUsernameLength {
		username = string([]rune(username)[:MaxUsernameLength])
	}

	userInfo.Username = username
	return userInfo
}

func (g *Connector) ConfigFields() []plugin.ConfigField {
	return []plugin.ConfigField{
		{
			Name:     "client_id",
			Type:     plugin.ConfigTypeInput,
			Title:    plugin.MakeTranslator(i18n.ConfigClientIDTitle),
			Required: true,
			UIOptions: plugin.ConfigFieldUIOptions{
				InputType: plugin.InputTypeText,
			},
			Value: g.Config.ClientID,
		},
		{
			Name:     "client_secret",
			Type:     plugin.ConfigTypeInput,
			Title:    plugin.MakeTranslator(i18n.ConfigClientSecretTitle),
			Required: true,
			UIOptions: plugin.ConfigFieldUIOptions{
				InputType: plugin.InputTypePassword,
			},
			Value: g.Config.ClientSecret,
		},
	}
}

func (g *Connector) ConfigReceiver(config []byte) error {
	c := &ConnectorConfig{}
	if err := json.Unmarshal(config, c); err != nil {
		return fmt.Errorf("failed to parse config: %w", err)
	}
	if len(c.ClientID) == 0 || len(c.ClientSecret) == 0 {
		return fmt.Errorf("client_id and client_secret are required")
	}
	g.Config = c
	// Initialize logo cache
	g.logoDataURI = getLogoDataURI()
	return nil
}

// Helper function to generate random strings for OAuth state
func randomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"
	chars := []rune(charset)
	result := make([]rune, length)
	for i := range result {
		result[i] = chars[rand.Intn(len(chars))]
	}
	return string(result)
}

// getLogoDataURICached returns the cached logo data URI
// If not cached yet, it reads and generates it on the fly
func (g *Connector) getLogoDataURICached() string {
	g.mu.RLock()
	if len(g.logoDataURI) > 0 {
		defer g.mu.RUnlock()
		return g.logoDataURI
	}
	g.mu.RUnlock()

	// Generate logo on first access (in case ConfigReceiver wasn't called)
	logoURI := getLogoDataURI()
	g.mu.Lock()
	g.logoDataURI = logoURI
	g.mu.Unlock()

	return logoURI
}

// getLogoDataURI reads the embedded EMlogo PNG and returns it as a base64 data URI
func getLogoDataURI() string {
	file, err := logoAssets.Open("assets/EMlogo-large1x.png")
	if err != nil {
		log.Warnf("failed to open logo: %v", err)
		return ""
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		log.Warnf("failed to read logo: %v", err)
		return ""
	}

	base64Data := base64.StdEncoding.EncodeToString(data)
	return fmt.Sprintf("data:image/png;base64,%s", base64Data)
}

// signatureResponse represents the response from VDS signature exchange endpoint
type signatureResponse struct {
	AccessToken      string `json:"accessToken"`
	ApiKey           string `json:"apiKey"`
	TokenType        string `json:"tokenType"`
	ExpiresInSeconds int    `json:"expiresInSeconds"`
	AppId            string `json:"appId"`
}

// getPlatformSignature retrieves and caches the VDS platform signature
// It implements automatic refresh with retry logic (max 3 attempts)
// Signature is refreshed when within 3 minutes of expiry (180 seconds)
func (g *Connector) getPlatformSignature() (string, error) {
	g.mu.RLock()
	if !g.signatureExpiry.IsZero() && time.Now().Add(3*time.Minute).Before(g.signatureExpiry) {
		signature := g.platformSignature
		g.mu.RUnlock()
		return signature, nil
	}
	g.mu.RUnlock()

	// Signature expired or not cached, request new one
	var lastErr error
	for attempt := 1; attempt <= 3; attempt++ {
		signature, expiry, err := g.requestSignature()
		if err == nil {
			g.mu.Lock()
			g.platformSignature = signature
			g.signatureExpiry = expiry
			g.mu.Unlock()
			log.Debugf("[VDS Connector] Successfully obtained platform signature (attempt %d)", attempt)
			return signature, nil
		}
		lastErr = err
		log.Warnf("[VDS Connector] Failed to obtain platform signature (attempt %d/%d): %v", attempt, 3, err)
		if attempt < 3 {
			time.Sleep(time.Duration(attempt) * time.Second) // exponential backoff
		}
	}

	return "", fmt.Errorf("failed to obtain platform signature after 3 attempts: %w", lastErr)
}

// requestSignature makes an HTTP request to VDS /api/auth/token endpoint
func (g *Connector) requestSignature() (string, time.Time, error) {
	payload := map[string]string{
		"clientId":     g.Config.ClientID,
		"clientSecret": g.Config.ClientSecret,
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("failed to marshal signature request: %w", err)
	}

	req, err := http.NewRequest("POST", SignatureURL, strings.NewReader(string(jsonData)))
	if err != nil {
		return "", time.Time{}, fmt.Errorf("failed to create signature request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: RequestTimeout * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("failed to request signature: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", time.Time{}, fmt.Errorf("signature request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var result signatureResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", time.Time{}, fmt.Errorf("failed to decode signature response: %w", err)
	}

	if len(result.AccessToken) == 0 {
		return "", time.Time{}, fmt.Errorf("empty access token in signature response")
	}

	// Calculate expiry time: now + expiresInSeconds - 3 minutes buffer
	expiryTime := time.Now().Add(time.Duration(result.ExpiresInSeconds)*time.Second - 3*time.Minute)
	return result.AccessToken, expiryTime, nil
}

// vdsTransport adds VDS platform signature to HTTP requests
type vdsTransport struct {
	platformSignature string
	base              http.RoundTripper
}

func (t *vdsTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Add platform signature to token exchange requests
	if strings.Contains(req.URL.String(), "/token") {
		if len(t.platformSignature) > 0 {
			req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", t.platformSignature))
		}
	}
	return t.base.RoundTrip(req)
}
