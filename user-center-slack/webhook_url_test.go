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

package slack_user_center

import "testing"

func TestValidateWebhookURL(t *testing.T) {
	for _, test := range []struct {
		url  string
		want bool
	}{
		{"https://hooks.slack.com/services/test", true},
		{"http://hooks.slack.com/services/test", false},
		{"https://127.0.0.1/services/test", false},
		{"https://hooks.slack.com.evil.test/services/test", false},
		{"https://hooks.slack.com:8443/services/test", false},
		{"https://user@hooks.slack.com/services/test", false},
	} {
		err := validateWebhookURL(test.url)
		if (err == nil) != test.want {
			t.Errorf("validateWebhookURL(%q) error = %v, want success = %t", test.url, err, test.want)
		}
	}
}
