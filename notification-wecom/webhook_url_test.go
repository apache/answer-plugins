/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0.
 */

package wecom

import "testing"

func TestValidateWebhookURL(t *testing.T) {
	for _, test := range []struct {
		url  string
		want bool
	}{
		{"https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=test", true},
		{"http://qyapi.weixin.qq.com/cgi-bin/webhook/send", false},
		{"https://127.0.0.1/cgi-bin/webhook/send", false},
		{"https://qyapi.weixin.qq.com.evil.test/cgi-bin/webhook/send", false},
		{"https://qyapi.weixin.qq.com:8443/cgi-bin/webhook/send", false},
		{"https://user@qyapi.weixin.qq.com/cgi-bin/webhook/send", false},
	} {
		err := validateWebhookURL(test.url)
		if (err == nil) != test.want {
			t.Errorf("validateWebhookURL(%q) error = %v, want success = %t", test.url, err, test.want)
		}
	}
}
