/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0.
 */

package slack_notification

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
