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
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/jimlambrt/gldap"
	"github.com/jimlambrt/gldap/testdirectory"
)

func newTestDirectoryEntry() *gldap.Entry {
	dn := "uid=" + testUsername + "," + testBaseDN
	return gldap.NewEntry(dn, map[string][]string{
		LdapAttributeUid:      {testUsername},
		LdapAttributeCn:       {testUsername},
		LdapAttributeMail:     {testEmail},
		DefaultExternalIDAttr: {testExternalID},
		"password":            {testPassword},
	})
}

func caCertFile(t *testing.T, pemCert string) string {
	path := filepath.Join(t.TempDir(), "ca.crt")
	if err := os.WriteFile(path, []byte(pemCert), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestIntegration_StartTLS(t *testing.T) {
	td := testdirectory.Start(t, testdirectory.WithNoTLS(t))
	td.SetUsers(newTestDirectoryEntry())

	c := &Connector{Config: &ConnectorConfig{
		Server:         fmt.Sprintf("ldap://%s:%d", td.Host(), td.Port()),
		BaseDN:         testBaseDN,
		BindDN:         "uid=" + testUsername + "," + testBaseDN,
		BindPassword:   testPassword,
		UserAttr:       LdapAttributeUid,
		ExternalIDAttr: DefaultExternalIDAttr,
		TLSCACertPath:  caCertFile(t, td.Cert()),
	}}

	userInfo, err := c.ConnectorReceiver(loginRequest(testUsername, testPassword), testReceiverURL)
	if err != nil {
		t.Fatal(err)
	}
	if userInfo.ExternalID != testExternalID {
		t.Fatalf("expected external ID %q, got %q", testExternalID, userInfo.ExternalID)
	}
}

func TestIntegration_LDAPS(t *testing.T) {
	td := testdirectory.Start(t)
	td.SetUsers(newTestDirectoryEntry())

	c := &Connector{Config: &ConnectorConfig{
		Server:         fmt.Sprintf("ldaps://%s:%d", td.Host(), td.Port()),
		BaseDN:         testBaseDN,
		BindDN:         "uid=" + testUsername + "," + testBaseDN,
		BindPassword:   testPassword,
		UserAttr:       LdapAttributeUid,
		ExternalIDAttr: DefaultExternalIDAttr,
		TLSCACertPath:  caCertFile(t, td.Cert()),
	}}

	userInfo, err := c.ConnectorReceiver(loginRequest(testUsername, testPassword), testReceiverURL)
	if err != nil {
		t.Fatal(err)
	}
	if userInfo.ExternalID != testExternalID {
		t.Fatalf("expected external ID %q, got %q", testExternalID, userInfo.ExternalID)
	}
}

func TestIntegration_PrivateCA_RejectedWithoutIt(t *testing.T) {
	td := testdirectory.Start(t)
	td.SetUsers(newTestDirectoryEntry())

	c := &Connector{Config: &ConnectorConfig{
		Server:         fmt.Sprintf("ldaps://%s:%d", td.Host(), td.Port()),
		BaseDN:         testBaseDN,
		BindDN:         "uid=" + testUsername + "," + testBaseDN,
		BindPassword:   testPassword,
		UserAttr:       LdapAttributeUid,
		ExternalIDAttr: DefaultExternalIDAttr,
	}}

	_, err := c.ConnectorReceiver(loginRequest(testUsername, testPassword), testReceiverURL)
	if err == nil {
		t.Fatal("expected the connection to fail without the private CA configured")
	}
}
