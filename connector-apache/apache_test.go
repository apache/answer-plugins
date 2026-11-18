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

package apache

import (
	"net/url"
	"testing"
)

func TestTokenURLPreservesCodeAsSingleParameter(t *testing.T) {
	for _, code := range []string{
		"normal-code",
		"code+with spaces",
		"code%2Fvalue",
		"code&grant_type=client_credentials",
		"授权码",
	} {
		tokenEndpoint, err := url.Parse(tokenURL(code))
		if err != nil {
			t.Fatalf("parse token URL: %v", err)
		}
		if tokenEndpoint.Scheme != "https" || tokenEndpoint.Host != "oauth.apache.org" || tokenEndpoint.Path != "/token" {
			t.Fatalf("unexpected token endpoint: %s", tokenEndpoint)
		}
		query := tokenEndpoint.Query()
		if len(query) != 1 || query.Get("code") != code {
			t.Errorf("tokenURL(%q) query = %#v, want only code=%q", code, query, code)
		}
	}
}
