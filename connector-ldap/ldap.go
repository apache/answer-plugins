package ldap

import (
	"embed"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/DanielAuerX/answer-plugins/connector-ldap/i18n"
	"github.com/segmentfault/pacman/log"

	"github.com/apache/answer-plugins/util"
	"github.com/apache/answer/plugin"
	"github.com/go-ldap/ldap/v3"
)

//go:embed  info.yaml
var Info embed.FS

//go:embed login.html
var loginHTML embed.FS

const (
	LdapAttributeDn             = "dn"
	LdapAttributeUid            = "uid"
	LdapAttributeCn             = "cn"
	LdapAttributeMail           = "mail"
	LdapAttributeDisplayName    = "displayName"
	LdapAttributeSamAccountName = "sAMAccountName"
)

type Connector struct {
	Config *ConnectorConfig
}

type ConnectorConfig struct {
	Name         string `json:"name"`
	Server       string `json:"server"`
	BaseDN       string `json:"base_dn"`
	BindPrefix   string `json:"bind_prefix"`   // e.g., uid=
	BindDN       string `json:"bind_dn"`       // service account DN
	BindPassword string `json:"bind_password"` // service account password
	UserAttr     string `json:"user_attr"`     // e.g., uid, sAMAccountName
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

func (g *Connector) ConnectorSlugName() string {
	return "ldap"
}

func (g *Connector) ConnectorLogoSVG() string {
	return ""
}

func (g *Connector) ConnectorSender(ctx *plugin.GinContext, receiverURL string) string {
	log.Info("LDAP connector ConnectorSender...")

	htmlContent, err := loginHTML.ReadFile("login.html")
	if err != nil {
		log.Errorf("failed to read embedded html file: %v", err)
		ctx.Writer.WriteHeader(500)
		ctx.Writer.Write([]byte("Internal Server Error"))
		return ""
	}

	ctx.Writer.WriteHeader(200)
	ctx.Writer.Header().Set("Content-Type", "text/html")
	_, _ = ctx.Writer.Write([]byte(fmt.Sprintf(string(htmlContent), receiverURL)))

	return ctx.Request.Host
}

// TODO get from translator
func (g *Connector) ConfigFields() []plugin.ConfigField {
	return []plugin.ConfigField{
		createTextInput("name", "LDAP", "LDAP connector name", g.Config.Name, true, false),
		createTextInput("server", "LDAP Server", "e.g. ldap.example.com:389", g.Config.Server, true, false),
		createTextInput("base_dn", "Base DN", "e.g. dc=example,dc=com", g.Config.BaseDN, true, false),
		createTextInput("bind_prefix", "Bind Prefix", "e.g. CN= or uid=", g.Config.BindPrefix, false, false), //TODO NOT USED YET
		createTextInput("bind_dn", "Bind DN", "DN of LDAP bind user", g.Config.BindDN, true, false),
		createTextInput("bind_password", "Bind Password", "Password for bind DN", g.Config.BindPassword, true, true),
		createTextInput("user_attr", "User Attribute", "LDAP attribute for username (e.g., uid or sAMAccountName)", g.Config.UserAttr, true, false),
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

func (c *Connector) ConnectorReceiver(ctx *plugin.GinContext, receiverURL string) (userInfo plugin.ExternalLoginUserInfo, err error) {
	log.Info("ConnectorReceiver called!")

	username, password, err := extractCredentials(ctx.Request)
	if err != nil {
		return userInfo, err
	}

	l, err := ldap.DialURL(c.Config.Server)
	if err != nil {
		return userInfo, fmt.Errorf("failed to connect to LDAP server: %w", err)
	}
	defer l.Close()

	err = l.Bind(c.Config.BindDN, c.Config.BindPassword)
	if err != nil {
		return userInfo, fmt.Errorf("bind failed: %w", err)
	}

	searchRequest := ldap.NewSearchRequest(
		c.Config.BaseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 1, 0, false,
		fmt.Sprintf("(%s=%s)", c.Config.UserAttr, ldap.EscapeFilter(username)),
		[]string{LdapAttributeDn, LdapAttributeUid, LdapAttributeCn, LdapAttributeMail, LdapAttributeDisplayName, LdapAttributeSamAccountName},
		nil,
	)

	sr, err := l.Search(searchRequest)
	if err != nil || len(sr.Entries) == 0 {
		return userInfo, fmt.Errorf("user not found: %w", err)
	}

	entry := sr.Entries[0]

	err = l.Bind(entry.DN, password)
	if err != nil {
		return userInfo, fmt.Errorf("invalid username or password")
	}

	userInfo = extractUserInfo(entry)

	log.Infof("userInfo %s", &userInfo)

	return userInfo, nil
}

func extractCredentials(request *http.Request) (username string, password string, err error) {
	queryParams := request.URL.Query()

	username = queryParams.Get("username")
	password = queryParams.Get("password")

	if username == "" || password == "" {
		log.Errorf("missing username or password")
		err = fmt.Errorf("missing username or password")
	}
	return
}

func extractUserInfo(entry *ldap.Entry) plugin.ExternalLoginUserInfo {

	displayName := entry.GetAttributeValue(LdapAttributeDisplayName)
	log.Infof("displayName %s", displayName)

	if displayName == "" {
		displayName = entry.GetAttributeValue(LdapAttributeCn)
	}

	username := entry.GetAttributeValue(LdapAttributeUid)
	if username == "" {
		username = entry.GetAttributeValue(LdapAttributeSamAccountName)
	}
	log.Infof("username %s", &username)

	externalID := username
	if externalID == "" {
		externalID = entry.DN // fallback
	}

	/*
	 email is used to login, therefore required.
	 wether the email is correct, is not important for our use case
	*/
	email := entry.GetAttributeValue(LdapAttributeMail)
	if email == "" {
		email = username + "@dummymail.xyz"
	}

	return plugin.ExternalLoginUserInfo{
		ExternalID:  externalID,
		DisplayName: displayName,
		Username:    username,
		Email:       email,
	}
}

func createTextInput(name, title, desc, value string, require bool, password bool) plugin.ConfigField {
	uiOptions := plugin.ConfigFieldUIOptions{
		InputType: plugin.InputTypeText,
	}
	if password {
		uiOptions = plugin.ConfigFieldUIOptions{
			InputType: plugin.InputTypePassword,
		}
	}
	return plugin.ConfigField{
		Name:        name,
		Type:        plugin.ConfigTypeInput,
		Title:       plugin.MakeTranslator(title),
		Description: plugin.MakeTranslator(desc),
		Required:    require,
		UIOptions:   uiOptions,
		Value:       value,
	}
}
