/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0.
 */

package dingtalk

import "testing"

func TestValidateWebhookURL(t *testing.T) {
	for _, test := range []struct {
		url  string
		want bool
	}{
		{"https://oapi.dingtalk.com/robot/send?access_token=test", true},
		{"http://oapi.dingtalk.com/robot/send", false},
		{"https://127.0.0.1/robot/send", false},
		{"https://oapi.dingtalk.com.evil.test/robot/send", false},
		{"https://oapi.dingtalk.com:8443/robot/send", false},
		{"https://user@oapi.dingtalk.com/robot/send", false},
	} {
		err := validateWebhookURL(test.url)
		if (err == nil) != test.want {
			t.Errorf("validateWebhookURL(%q) error = %v, want success = %t", test.url, err, test.want)
		}
	}
}
