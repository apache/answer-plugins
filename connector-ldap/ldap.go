package ldap

import (
	"embed"
	"encoding/json"
	"fmt"

	"github.com/apache/answer-plugins/connector-ldap/i18n"
	"github.com/apache/answer-plugins/util"
	"github.com/apache/answer/plugin"
	"github.com/go-ldap/ldap/v3"
)

// TODO: sanitization (e.g. username)
// TODO: email and display name lookup from ldap?
var Info embed.FS

type Connector struct {
	Config *ConnectorConfig
}

type ConnectorConfig struct {
	Name       string `json:"name"`
	Server     string `json:"server"`
	BaseDN     string `json:"base_dn"`
	BindPrefix string `json:"bind_prefix"`
}

var _ plugin.Connector = &Connector{}

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

func (g *Connector) ConnectorName() plugin.Translator {
	if g.Config.Name != "" {
		return plugin.MakeTranslator(g.Config.Name)
	}
	return plugin.MakeTranslator(i18n.ConnectorName)
}

// get from info.yaml? != ldap
func (g *Connector) ConnectorSlugName() string {
	return "ldap"
}

// TODO: SVG support?
func (g *Connector) ConnectorLogoSVG() string {
	return ""
}

// TODO get from translator
func (g *Connector) ConfigFields() []plugin.ConfigField {
	return []plugin.ConfigField{
		createTextInput("name", "LDAP", "LDAP connector name", g.Config.Name, true),
		createTextInput("server", "LDAP Server", "e.g. ldap.example.com:389", g.Config.Server, true),
		createTextInput("base_dn", "Base DN", "e.g. dc=example,dc=com", g.Config.BaseDN, true),
		createTextInput("bind_prefix", "Bind Prefix", "e.g. CN= or uid=", g.Config.BindPrefix, false),
	}
}

func (g *Connector) ConfigReceiver(config []byte) error {
	c := &ConnectorConfig{}
	if err := json.Unmarshal(config, c); err != nil {
		return err
	}
	g.Config = c
	return nil
}

func (g *Connector) ConnectorReceiver(ctx *plugin.GinContext, receiverURL string) (plugin.ExternalLoginUserInfo, error) {
	var userInfo plugin.ExternalLoginUserInfo

	username := ctx.Request.FormValue("username")
	password := ctx.Request.FormValue("password")
	if username == "" || password == "" {
		return userInfo, fmt.Errorf("missing username or password")
	}

	bindDN := fmt.Sprintf("%s%s,%s", g.Config.BindPrefix, username, g.Config.BaseDN)

	err := ldapAuthenticate(g.Config.Server, g.Config.BaseDN, bindDN, password)
	if err != nil {
		return userInfo, fmt.Errorf("LDAP auth failed: %s", err)
	}

	// returning to answer core
	userInfo = plugin.ExternalLoginUserInfo{
		ExternalID:  bindDN,
		DisplayName: username,
		Username:    username,
		Email:       fmt.Sprintf("%s@example.com", username), // optional, needed?
		MetaInfo:    fmt.Sprintf("LDAP user %s", username),
	}
	return userInfo, nil
}

func ldapAuthenticate(server, baseDN, bindDN, password string) error {
	l, err := ldap.Dial("tcp", server)
	if err != nil {
		return err
	}
	defer l.Close()

	// bind with user credentials
	err = l.Bind(bindDN, password)
	if err != nil {
		return err
	}

	// search user info?

	return nil
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
