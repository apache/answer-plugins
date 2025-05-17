package ldap

import (
	"crypto/tls"
	"crypto/x509"
	"embed"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

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
	Name          string `json:"name"`
	Server        string `json:"server"`
	BaseDN        string `json:"base_dn"`
	BindDN        string `json:"bind_dn"`
	BindPassword  string `json:"bind_password"`
	UserAttr      string `json:"user_attr"`
	TLSCACertPath string `json:"tls_ca_cert_path"`
}

var _ plugin.Connector = &Connector{}

var loginHTMLContent string

func init() {
	plugin.Register(&Connector{
		Config: &ConnectorConfig{},
	})

	htmlContent, err := loginHTML.ReadFile("login.html")
	if err != nil {
		log.Errorf("failed to read embedded html file: %v", err)
	}
	loginHTMLContent = string(htmlContent)
	if "" == loginHTMLContent {
		log.Error("html file is empty")
	}
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

	htmlContent := strings.Replace(loginHTMLContent, "RECEIVER_URL_PLACEHOLDER", receiverURL, -1)
	ctx.Writer.WriteHeader(200)
	ctx.Writer.Header().Set("Content-Type", "text/html")
	err := writeHtmlContent(ctx, htmlContent)
	if err != nil {
		log.Errorf("failed to write HTML response: %v", err)
	}

	return ""
}

func writeHtmlContent(ctx *plugin.GinContext, htmlContent string) error {
	ctx.Writer.WriteHeader(200)
	ctx.Writer.Header().Set("Content-Type", "text/html")
	_, err := ctx.Writer.Write([]byte(htmlContent))
	return err
}

// TODO get from translator
func (g *Connector) ConfigFields() []plugin.ConfigField {
	return []plugin.ConfigField{
		createTextInput("name", "LDAP", "LDAP connector name", g.Config.Name, true, false),
		createTextInput("server", "LDAP Server", "e.g. ldaps://ldap.example.com:636", g.Config.Server, true, false),
		createTextInput("base_dn", "Base DN", "e.g. dc=example,dc=com", g.Config.BaseDN, true, false),
		createTextInput("bind_dn", "Bind DN", "DN of LDAP bind user", g.Config.BindDN, true, false),
		createTextInput("bind_password", "Bind Password", "Password for bind DN", g.Config.BindPassword, true, true),
		createTextInput("user_attr", "User Attribute", "LDAP attribute for username (e.g., uid or sAMAccountName)", g.Config.UserAttr, true, false),
		createTextInput("tls_ca_cert_path", "TLS CA Certificate Path", "Path to custom CA certificate file (optional)", g.Config.TLSCACertPath, false, false),
	}
}

func (g *Connector) ConfigReceiver(config []byte) error {
	c := &ConnectorConfig{}
	if err := json.Unmarshal(config, c); err != nil {
		return fmt.Errorf("invalid config json: %w", err)
	}
	g.Config = c
	return nil
}

func (c *Connector) ConnectorReceiver(ctx *plugin.GinContext, receiverURL string) (userInfo plugin.ExternalLoginUserInfo, err error) {

	username, password, err := extractCredentials(ctx.Request)
	if err != nil {
		return userInfo, err
	}

	l, err := dialWithTLS(c.Config.Server, c.Config.TLSCACertPath)
	if err != nil {
		return userInfo, fmt.Errorf("failed to connect to LDAP server: %w", err)
	}
	defer l.Close()

	if err := bindServiceAccount(l, c.Config.BindDN, c.Config.BindPassword); err != nil {
		return userInfo, fmt.Errorf("service account bind failed: %w", err)
	}

	entry, err := searchUser(l, c.Config.BaseDN, c.Config.UserAttr, username)
	if err != nil {
		return userInfo, err
	}

	err = l.Bind(entry.DN, password)
	if err != nil {
		return userInfo, fmt.Errorf("invalid username or password")
	}

	userInfo, err = extractUserInfo(entry)
	if err != nil {
		return userInfo, err
	}

	return userInfo, nil
}

func bindServiceAccount(l *ldap.Conn, bindDN, bindPassword string) error {
	return l.Bind(bindDN, bindPassword)
}

func searchUser(l *ldap.Conn, baseDN, userAttr, username string) (*ldap.Entry, error) {
	searchRequest := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 1, 0, false,
		fmt.Sprintf("(%s=%s)", userAttr, ldap.EscapeFilter(username)),
		[]string{LdapAttributeDn, LdapAttributeUid, LdapAttributeCn, LdapAttributeMail, LdapAttributeDisplayName, LdapAttributeSamAccountName},
		nil,
	)

	sr, err := l.Search(searchRequest)
	if err != nil || len(sr.Entries) == 0 {
		return nil, fmt.Errorf("user not found: %w", err)
	}

	return sr.Entries[0], nil
}

func extractCredentials(request *http.Request) (username string, password string, err error) {
	err = request.ParseForm()
	if err != nil {
		log.Errorf("failed to parse form: %v", err)
		return "", "", err
	}

	username = request.FormValue("username")
	password = request.FormValue("password")

	if username == "" || password == "" {
		log.Errorf("missing username and/or password")
		err = fmt.Errorf("missing username or password")
	}
	return
}

func extractUserInfo(entry *ldap.Entry) (plugin.ExternalLoginUserInfo, error) {

	displayName := entry.GetAttributeValue(LdapAttributeDisplayName)

	if displayName == "" {
		displayName = entry.GetAttributeValue(LdapAttributeCn)
	}

	username := entry.GetAttributeValue(LdapAttributeUid)
	if username == "" {
		username = entry.GetAttributeValue(LdapAttributeSamAccountName)
	}

	externalID := username
	if externalID == "" {
		externalID = entry.DN // fallback
	}

	//email is used to login, therefore required
	email := entry.GetAttributeValue(LdapAttributeMail)
	if email == "" {
		return nil, fmt.Errorf("email is required")
	}

	return plugin.ExternalLoginUserInfo{
		ExternalID:  externalID,
		DisplayName: displayName,
		Username:    username,
		Email:       email,
	}, nil
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

func createBoolInput(name, title, desc string, value bool, require bool) plugin.ConfigField {
	return plugin.ConfigField{

		Name:        name,
		Type:        plugin.ConfigTypeCheckbox,
		Title:       plugin.MakeTranslator(title),
		Description: plugin.MakeTranslator(desc),
		Required:    require,
		UIOptions:   plugin.ConfigFieldUIOptions{},
		Value:       value,
	}

}

func dialWithTLS(server string, certPath string) (*ldap.Conn, error) {

	tlsConfig := &tls.Config{
		InsecureSkipVerify: false,
	}

	if certPath != "" {
		certPool := x509.NewCertPool()
		certData, err := os.ReadFile(certPath)
		if err != nil {
			log.Errorf("failed to read cert file: %v", err)
			return nil, fmt.Errorf("failed to read LDAP cert: %w", err)
		}

		if !certPool.AppendCertsFromPEM(certData) {
			log.Errorf("failed to append cert from %s", certPath)
			return nil, fmt.Errorf("failed to append cert")
		}

		tlsConfig.RootCAs = certPool
	}

	if strings.HasPrefix(server, "ldaps://") {
		return ldap.DialURL(server, ldap.DialWithTLSConfig(tlsConfig))
	}

	conn, err := ldap.DialURL(server)
	if err != nil {
		log.Errorf("initial plain connection failed: %v", err)
		return nil, err
	}

	if err := conn.StartTLS(tlsConfig); err != nil {
		log.Errorf("startTLS failed: %v", err)
		conn.Close()
		return nil, err
	}

	return conn, nil
}
