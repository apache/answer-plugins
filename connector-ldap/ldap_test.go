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

package ldap

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	goldap "github.com/go-ldap/ldap/v3"
)

type mockLDAPClient struct {
	bindFunc   func(username, password string) error
	searchFunc func(req *goldap.SearchRequest) (*goldap.SearchResult, error)
}

var _ goldap.Client = &mockLDAPClient{}

const (
	testUsername     = "mickeyMouse"
	testPassword     = "iLoveMinnieMouse"
	testEmail        = "mickey@test.com"
	testExternalID   = "01234567-89ab-cdef-0123-456789abcdef"
	testServer       = "ldap://localhost:389"
	testBaseDN       = "dc=example,dc=com"
	testBindDN       = "cn=admin,dc=example,dc=com"
	testBindPassword = "admin-password"
	testReceiverURL  = "http://localhost:8080/answer/api/v1/connector/redirect/ldap"
	testOrigin       = "http://localhost:8080"
)

func (m *mockLDAPClient) Start()                     {}
func (m *mockLDAPClient) StartTLS(*tls.Config) error { return nil }
func (m *mockLDAPClient) Close() error               { return nil }
func (m *mockLDAPClient) GetLastError() error        { return nil }
func (m *mockLDAPClient) IsClosing() bool            { return false }
func (m *mockLDAPClient) SetTimeout(time.Duration)   {}
func (m *mockLDAPClient) TLSConnectionState() (tls.ConnectionState, bool) {
	return tls.ConnectionState{}, false
}

func (m *mockLDAPClient) Bind(username, password string) error {
	return m.bindFunc(username, password)
}
func (m *mockLDAPClient) UnauthenticatedBind(username string) error { return nil }
func (m *mockLDAPClient) SimpleBind(*goldap.SimpleBindRequest) (*goldap.SimpleBindResult, error) {
	return nil, nil
}
func (m *mockLDAPClient) ExternalBind() error                                   { return nil }
func (m *mockLDAPClient) NTLMUnauthenticatedBind(domain, username string) error { return nil }
func (m *mockLDAPClient) Unbind() error                                         { return nil }

func (m *mockLDAPClient) Add(*goldap.AddRequest) error       { return nil }
func (m *mockLDAPClient) Del(*goldap.DelRequest) error       { return nil }
func (m *mockLDAPClient) Modify(*goldap.ModifyRequest) error { return nil }
func (m *mockLDAPClient) ModifyDN(*goldap.ModifyDNRequest) error {
	return nil
}
func (m *mockLDAPClient) ModifyWithResult(*goldap.ModifyRequest) (*goldap.ModifyResult, error) {
	return nil, nil
}
func (m *mockLDAPClient) Extended(*goldap.ExtendedRequest) (*goldap.ExtendedResponse, error) {
	return nil, nil
}

func (m *mockLDAPClient) Compare(dn, attribute, value string) (bool, error) {
	return false, nil
}
func (m *mockLDAPClient) PasswordModify(*goldap.PasswordModifyRequest) (*goldap.PasswordModifyResult, error) {
	return nil, nil
}

func (m *mockLDAPClient) Search(req *goldap.SearchRequest) (*goldap.SearchResult, error) {
	return m.searchFunc(req)
}
func (m *mockLDAPClient) SearchAsync(ctx context.Context, req *goldap.SearchRequest, bufferSize int) goldap.Response {
	return nil
}
func (m *mockLDAPClient) SearchWithPaging(*goldap.SearchRequest, uint32) (*goldap.SearchResult, error) {
	return nil, nil
}
func (m *mockLDAPClient) DirSync(req *goldap.SearchRequest, flags, maxAttrCount int64, cookie []byte) (*goldap.SearchResult, error) {
	return nil, nil
}
func (m *mockLDAPClient) DirSyncAsync(ctx context.Context, req *goldap.SearchRequest, bufferSize int, flags, maxAttrCount int64, cookie []byte) goldap.Response {
	return nil
}
func (m *mockLDAPClient) Syncrepl(ctx context.Context, req *goldap.SearchRequest, bufferSize int, mode goldap.ControlSyncRequestMode, cookie []byte, reloadHint bool) goldap.Response {
	return nil
}

func withMockLDAP(t *testing.T, mock *mockLDAPClient) {
	original := connectLDAP
	connectLDAP = func(server, certPath string) (goldap.Client, error) {
		return mock, nil
	}
	t.Cleanup(func() { connectLDAP = original })
}

func testEntry(username, email, externalIDAttr, externalIDValue string) *goldap.Entry {
	return &goldap.Entry{
		DN: "uid=" + username + "," + testBaseDN,
		Attributes: []*goldap.EntryAttribute{
			{Name: LdapAttributeUid, Values: []string{username}},
			{Name: LdapAttributeCn, Values: []string{username}},
			{Name: LdapAttributeMail, Values: []string{email}},
			{Name: externalIDAttr, Values: []string{externalIDValue}},
		},
	}
}

func loginRequest(username, password string) *gin.Context {
	form := url.Values{"username": {username}, "password": {password}}
	req := httptest.NewRequest("POST", "/answer/api/v1/connector/redirect/ldap", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", testOrigin)
	ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
	ctx.Request = req
	return ctx
}

func TestConnector_SenderIncludesStateDespiteGinQueryCache(t *testing.T) {
	c := &Connector{Config: &ConnectorConfig{}}

	req := httptest.NewRequest("GET", "/answer/api/v1/connector/login/ldap", nil)
	rec := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(rec)
	ctx.Request = req

	ctx.Query("state")
	ctx.Request.URL.RawQuery = "state=injected-after-cache"

	c.ConnectorSender(ctx, "https://example.com/answer/api/v1/connector/redirect/ldap")

	if !strings.Contains(rec.Body.String(), "state=injected-after-cache") {
		t.Fatalf("expected rendered form action to include the state injected after gin's query cache was primed, got: %s", rec.Body.String())
	}
}

func TestConnector_SuccessfulLogin(t *testing.T) {
	entry := testEntry(testUsername, testEmail, DefaultExternalIDAttr, testExternalID)
	withMockLDAP(t, &mockLDAPClient{
		bindFunc: func(username, password string) error {
			if username == testBindDN {
				return nil
			}
			if username == entry.DN && password == testPassword {
				return nil
			}
			return fmt.Errorf("invalid credentials")
		},
		searchFunc: func(req *goldap.SearchRequest) (*goldap.SearchResult, error) {
			return &goldap.SearchResult{Entries: []*goldap.Entry{entry}}, nil
		},
	})

	c := &Connector{Config: &ConnectorConfig{
		Server:         testServer,
		BaseDN:         testBaseDN,
		BindDN:         testBindDN,
		BindPassword:   testBindPassword,
		UserAttr:       LdapAttributeUid,
		ExternalIDAttr: DefaultExternalIDAttr,
	}}

	userInfo, err := c.ConnectorReceiver(loginRequest(testUsername, testPassword), testReceiverURL)
	if err != nil {
		t.Fatal(err)
	}
	if userInfo.Email != testEmail {
		t.Fatalf("expected email %q, got %q", testEmail, userInfo.Email)
	}
	if userInfo.ExternalID != testExternalID {
		t.Fatalf("expected external ID from entryUUID, got %q", userInfo.ExternalID)
	}
}

func TestConnector_ServiceAccountBindFailure(t *testing.T) {
	withMockLDAP(t, &mockLDAPClient{
		bindFunc: func(username, password string) error {
			return fmt.Errorf("invalid credentials")
		},
		searchFunc: func(req *goldap.SearchRequest) (*goldap.SearchResult, error) {
			t.Fatal("search should not be called when the service account bind fails")
			return nil, nil
		},
	})

	c := &Connector{Config: &ConnectorConfig{
		Server:         testServer,
		BaseDN:         testBaseDN,
		BindDN:         testBindDN,
		BindPassword:   "wrongPassword",
		UserAttr:       LdapAttributeUid,
		ExternalIDAttr: DefaultExternalIDAttr,
	}}

	_, err := c.ConnectorReceiver(loginRequest(testUsername, "correctPassword"), testReceiverURL)
	if err == nil {
		t.Fatal("expected service account bind failure to produce an error")
	}
}

func TestConnector_UserNotFound(t *testing.T) {
	withMockLDAP(t, &mockLDAPClient{
		bindFunc: func(username, password string) error { return nil },
		searchFunc: func(req *goldap.SearchRequest) (*goldap.SearchResult, error) {
			return &goldap.SearchResult{Entries: nil}, nil
		},
	})

	c := &Connector{Config: &ConnectorConfig{
		Server:         testServer,
		BaseDN:         testBaseDN,
		BindDN:         testBindDN,
		BindPassword:   testBindPassword,
		UserAttr:       LdapAttributeUid,
		ExternalIDAttr: DefaultExternalIDAttr,
	}}

	_, err := c.ConnectorReceiver(loginRequest("foo", "bar"), testReceiverURL)
	if err == nil {
		t.Fatal("expected an error when the user search returns no entries")
	}
}

func TestConnector_WrongPassword(t *testing.T) {
	entry := testEntry(testUsername, testEmail, DefaultExternalIDAttr, testExternalID)
	withMockLDAP(t, &mockLDAPClient{
		bindFunc: func(username, password string) error {
			if username == testBindDN {
				return nil
			}
			return fmt.Errorf("invalid credentials")
		},
		searchFunc: func(req *goldap.SearchRequest) (*goldap.SearchResult, error) {
			return &goldap.SearchResult{Entries: []*goldap.Entry{entry}}, nil
		},
	})

	c := &Connector{Config: &ConnectorConfig{
		Server:         testServer,
		BaseDN:         testBaseDN,
		BindDN:         testBindDN,
		BindPassword:   testBindPassword,
		UserAttr:       LdapAttributeUid,
		ExternalIDAttr: DefaultExternalIDAttr,
	}}

	_, err := c.ConnectorReceiver(loginRequest(testUsername, "iAmAWrongPassword"), testReceiverURL)
	if err == nil {
		t.Fatal("expected wrong password to produce an error")
	}
}

func TestCheckSameOrigin_MatchingOrigin(t *testing.T) {
	req := loginRequest(testUsername, testPassword).Request
	if err := checkSameOrigin(req, testReceiverURL); err != nil {
		t.Fatal(err)
	}
}

func TestCheckSameOrigin_MatchingReferer(t *testing.T) {
	req := loginRequest(testUsername, testPassword).Request
	req.Header.Del("Origin")
	req.Header.Set("Referer", testReceiverURL+"?state=foo")
	if err := checkSameOrigin(req, testReceiverURL); err != nil {
		t.Fatal(err)
	}
}

func TestCheckSameOrigin_MismatchedOrigin(t *testing.T) {
	req := loginRequest(testUsername, testPassword).Request
	req.Header.Set("Origin", "https://definitely.not.evil.com")
	if err := checkSameOrigin(req, testReceiverURL); err == nil {
		t.Fatal("expected a mismatched Origin header to be rejected")
	}
}

func TestCheckSameOrigin_MissingHeaders(t *testing.T) {
	req := loginRequest(testUsername, testPassword).Request
	req.Header.Del("Origin")
	if err := checkSameOrigin(req, testReceiverURL); err == nil {
		t.Fatal("expected a request with no Origin or Referer header to be rejected")
	}
}

func TestExtractCredentials(t *testing.T) {
	req := loginRequest(testUsername, testPassword).Request
	username, password, err := extractCredentials(req)
	if err != nil {
		t.Fatal(err)
	}
	if username != testUsername || password != testPassword {
		t.Fatalf("expected %q/%q, got %q/%q", testUsername, testPassword, username, password)
	}
}

func TestExtractCredentials_Missing(t *testing.T) {
	req := loginRequest(testUsername, "").Request
	if _, _, err := extractCredentials(req); err == nil {
		t.Fatal("expected an error when the password is missing")
	}
}

func TestExtractUserInfo_MissingEmail(t *testing.T) {
	entry := testEntry(testUsername, "", DefaultExternalIDAttr, testExternalID)
	if _, err := extractUserInfo(entry, DefaultExternalIDAttr); err == nil {
		t.Fatal("expected an error when the mail attribute is missing")
	}
}

func TestExtractExternalID_MissingAttribute(t *testing.T) {
	entry := testEntry(testUsername, testEmail, DefaultExternalIDAttr, "")
	entry.Attributes = entry.Attributes[:len(entry.Attributes)-1]
	if _, err := extractExternalID(entry, DefaultExternalIDAttr); err == nil {
		t.Fatal("expected an error when the configured external ID attribute is missing")
	}
}

func TestExtractExternalID_ObjectGUID(t *testing.T) {
	entry := &goldap.Entry{
		DN: "cn=" + testUsername + "," + testBaseDN,
		Attributes: []*goldap.EntryAttribute{
			{
				Name:       LdapAttributeObjectGUID,
				ByteValues: [][]byte{{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}},
			},
		},
	}

	externalID, err := extractExternalID(entry, LdapAttributeObjectGUID)
	if err != nil {
		t.Fatal(err)
	}
	const expected = "04030201-0605-0807-090a-0b0c0d0e0f10"
	if externalID != expected {
		t.Fatalf("expected %q, got %q", expected, externalID)
	}
}
