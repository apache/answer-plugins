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

package basic

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/apache/answer-plugins/connector-basic/i18n"
	"github.com/apache/answer-plugins/util"
	"github.com/apache/answer/pkg/checker"
	"github.com/apache/answer/plugin"
	"github.com/segmentfault/pacman/log"
	"github.com/tidwall/gjson"
	"golang.org/x/oauth2"
)

var (
	replaceUsernameReg = regexp.MustCompile(`[^a-zA-Z0-9._-]+`)
	//go:embed  info.yaml
	Info embed.FS
)

type Connector struct {
	Config *ConnectorConfig
}

type ConnectorConfig struct {
	Name string `json:"name"`

	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	AuthorizeUrl string `json:"authorize_url"`
	TokenUrl     string `json:"token_url"`
	UserJsonUrl  string `json:"user_json_url"`

	UserIDJsonPath          string `json:"user_id_json_path"`
	UserDisplayNameJsonPath string `json:"user_display_name_json_path"`
	UserUsernameJsonPath    string `json:"user_username_json_path"`
	UserEmailJsonPath       string `json:"user_email_json_path"`
	UserAvatarJsonPath      string `json:"user_avatar_json_path"`

	CheckEmailVerified    bool   `json:"check_email_verified"`
	EmailVerifiedJsonPath string `json:"email_verified_json_path"`

	Scope   string `json:"scope"`
	LogoSVG string `json:"logo_svg"`
}

var base64chars = strings.Split("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_", "")

func randomString(length int) (ret string) {
	l := len(base64chars)
	for i := 0; i < length; i++ {
		ret = ret + base64chars[rand.Intn(l)]
	}
	return
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
	return g.Config.LogoSVG
}

func (g *Connector) ConnectorName() plugin.Translator {
	if len(g.Config.Name) > 0 {
		return plugin.MakeTranslator(g.Config.Name)
	}
	return plugin.MakeTranslator(i18n.ConnectorName)
}

func (g *Connector) ConnectorSlugName() string {
	return "basic"
}

func (g *Connector) ConnectorSender(ctx *plugin.GinContext, receiverURL string) (redirectURL string) {
	oauth2Config := &oauth2.Config{
		ClientID:     g.Config.ClientID,
		ClientSecret: g.Config.ClientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:  g.Config.AuthorizeUrl,
			TokenURL: g.Config.TokenUrl,
		},
		RedirectURL: receiverURL,
		Scopes:      strings.Split(g.Config.Scope, ","),
	}
	state := randomString(24)
	return oauth2Config.AuthCodeURL(state)
}

func (g *Connector) ConnectorReceiver(ctx *plugin.GinContext, receiverURL string) (userInfo plugin.ExternalLoginUserInfo, err error) {
	code := ctx.Query("code")
	// Exchange code for token
	oauth2Config := &oauth2.Config{
		ClientID:     g.Config.ClientID,
		ClientSecret: g.Config.ClientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:   g.Config.AuthorizeUrl,
			TokenURL:  g.Config.TokenUrl,
			AuthStyle: oauth2.AuthStyleAutoDetect,
		},
		RedirectURL: receiverURL,
	}
	token, err := oauth2Config.Exchange(context.Background(), code)
	if err != nil {
		return userInfo, fmt.Errorf("code exchange failed: %s", err.Error())
	}

	// Exchange token for user info
	client := oauth2.NewClient(context.Background(), oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: token.AccessToken},
	))
	client.Timeout = 15 * time.Second

	response, err := client.Get(g.Config.UserJsonUrl)
	if err != nil {
		return userInfo, fmt.Errorf("failed getting user info: %s", err.Error())
	}
	defer response.Body.Close()
	data, _ := io.ReadAll(response.Body)

	userInfo = plugin.ExternalLoginUserInfo{
		MetaInfo: string(data),
	}

	if len(g.Config.UserIDJsonPath) > 0 {
		userInfo.ExternalID = gjson.GetBytes(data, g.Config.UserIDJsonPath).String()
	}
	if len(userInfo.ExternalID) == 0 {
		log.Errorf("fail to get user id from json path: %s", g.Config.UserIDJsonPath)
		return userInfo, nil
	}
	if len(g.Config.UserDisplayNameJsonPath) > 0 {
		userInfo.DisplayName = gjson.GetBytes(data, g.Config.UserDisplayNameJsonPath).String()
	}
	if len(g.Config.UserUsernameJsonPath) > 0 {
		userInfo.Username = gjson.GetBytes(data, g.Config.UserUsernameJsonPath).String()
	}
	if len(g.Config.UserEmailJsonPath) > 0 {
		userInfo.Email = gjson.GetBytes(data, g.Config.UserEmailJsonPath).String()
	}
	if g.Config.CheckEmailVerified && len(g.Config.EmailVerifiedJsonPath) > 0 {
		emailVerified := gjson.GetBytes(data, g.Config.EmailVerifiedJsonPath).Bool()
		if !emailVerified {
			userInfo.Email = ""
		}
	}
	if len(g.Config.UserAvatarJsonPath) > 0 {
		userInfo.Avatar = gjson.GetBytes(data, g.Config.UserAvatarJsonPath).String()
	}

	userInfo = g.formatUserInfo(userInfo)
	return userInfo, nil
}

func (g *Connector) formatUserInfo(userInfo plugin.ExternalLoginUserInfo) (
	userInfoFormatted plugin.ExternalLoginUserInfo) {
	userInfoFormatted = userInfo
	if checker.IsInvalidUsername(userInfoFormatted.Username) {
		userInfoFormatted.Username = replaceUsernameReg.ReplaceAllString(userInfoFormatted.Username, "_")
	}

	usernameLength := utf8.RuneCountInString(userInfoFormatted.Username)
	if usernameLength < 4 {
		userInfoFormatted.Username = userInfoFormatted.Username + strings.Repeat("_", 4-usernameLength)
	} else if usernameLength > 30 {
		userInfoFormatted.Username = string([]rune(userInfoFormatted.Username)[:30])
	}
	return userInfoFormatted
}

func (g *Connector) ConfigFields() []plugin.ConfigField {
	fields := make([]plugin.ConfigField, 0)
	fields = append(fields, createTextInput("name",
		i18n.ConfigNameTitle, i18n.ConfigNameDescription, g.Config.Name, true))
	fields = append(fields, createTextInput("client_id",
		i18n.ConfigClientIDTitle, i18n.ConfigClientIDDescription, g.Config.ClientID, true))
	fields = append(fields, createTextInput("client_secret",
		i18n.ConfigClientSecretTitle, i18n.ConfigClientSecretDescription, g.Config.ClientSecret, true))
	fields = append(fields, createTextInput("authorize_url",
		i18n.ConfigAuthorizeUrlTitle, i18n.ConfigAuthorizeUrlDescription, g.Config.AuthorizeUrl, true))
	fields = append(fields, createTextInput("token_url",
		i18n.ConfigTokenUrlTitle, i18n.ConfigTokenUrlDescription, g.Config.TokenUrl, true))
	fields = append(fields, createTextInput("user_json_url",
		i18n.ConfigUserJsonUrlTitle, i18n.ConfigUserJsonUrlDescription, g.Config.UserJsonUrl, true))
	fields = append(fields, createTextInput("user_id_json_path",
		i18n.ConfigUserIDJsonPathTitle, i18n.ConfigUserIDJsonPathDescription, g.Config.UserIDJsonPath, true))
	fields = append(fields, createTextInput("user_display_name_json_path",
		i18n.ConfigUserDisplayNameJsonPathTitle, i18n.ConfigUserDisplayNameJsonPathDescription, g.Config.UserDisplayNameJsonPath, false))
	fields = append(fields, createTextInput("user_username_json_path",
		i18n.ConfigUserUsernameJsonPathTitle, i18n.ConfigUserUsernameJsonPathDescription, g.Config.UserUsernameJsonPath, false))
	fields = append(fields, createTextInput("user_email_json_path",
		i18n.ConfigUserEmailJsonPathTitle, i18n.ConfigUserEmailJsonPathDescription, g.Config.UserEmailJsonPath, false))
	fields = append(fields, createTextInput("user_avatar_json_path",
		i18n.ConfigUserAvatarJsonPathTitle, i18n.ConfigUserAvatarJsonPathDescription, g.Config.UserAvatarJsonPath, false))
	fields = append(fields, plugin.ConfigField{
		Name:  "check_email_verified",
		Type:  plugin.ConfigTypeSwitch,
		Title: plugin.MakeTranslator(i18n.ConfigCheckEmailVerifiedTitle),
		Value: g.Config.CheckEmailVerified,
		UIOptions: plugin.ConfigFieldUIOptions{
			Label: plugin.MakeTranslator(i18n.ConfigCheckEmailVerifiedLabel),
		},
	})
	fields = append(fields, createTextInput("email_verified_json_path",
		i18n.ConfigEmailVerifiedJsonPathTitle, i18n.ConfigEmailVerifiedJsonPathDescription, g.Config.EmailVerifiedJsonPath, false))
	fields = append(fields, createTextInput("scope",
		i18n.ConfigScopeTitle, i18n.ConfigScopeDescription, g.Config.Scope, false))
	fields = append(fields, createTextInput("logo_svg",
		i18n.ConfigLogoSVGTitle, i18n.ConfigLogoSVGDescription, g.Config.LogoSVG, false))

	return fields
}

func createTextInput(name, title, desc, value string, require bool) plugin.ConfigField {
	return plugin.ConfigField{
		Name:        name,
		Type:        plugin.ConfigTypeInput,
		Title:       plugin.MakeTranslator(title),
		Description: plugin.MakeTranslator(desc),
		Required:    require,
		UIOptions: plugin.ConfigFieldUIOptions{
			InputType: plugin.InputTypeText,
		},
		Value: value,
	}
}

func (g *Connector) ConfigReceiver(config []byte) error {
	c := &ConnectorConfig{}
	_ = json.Unmarshal(config, c)
	g.Config = c
	return nil
}
