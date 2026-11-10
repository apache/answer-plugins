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

package redis

import (
	"context"
	"crypto/tls"
	"embed"
	_ "embed"
	"encoding/json"
	"fmt"
	"time"

	"github.com/apache/answer-plugins/cache-redis/i18n"
	"github.com/apache/answer-plugins/util"
	"github.com/apache/answer/plugin"
	"github.com/go-redis/redis/v8"
)

var (
	configuredErr = fmt.Errorf("redis is not configured correctly")
	//go:embed  info.yaml
	Info embed.FS
)

type Cache struct {
	Config      *CacheConfig
	RedisClient *redis.Client
}

type CacheConfig struct {
	Endpoint      string `json:"endpoint"`
	Username      string `json:"username"`
	Password      string `json:"password"`
	TLSEnabled    bool   `json:"tls_enabled"`
	TLSSkipVerify bool   `json:"tls_skip_verify"`
}

func init() {
	plugin.Register(&Cache{
		Config: &CacheConfig{},
	})
}

func (c *Cache) Info() plugin.Info {
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

func (c *Cache) GetString(ctx context.Context, key string) (data string, exist bool, err error) {
	if c.RedisClient == nil {
		return "", false, configuredErr
	}
	data, err = c.RedisClient.Get(ctx, key).Result()
	if err == redis.Nil {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return data, true, nil
}

func (c *Cache) SetString(ctx context.Context, key, value string, ttl time.Duration) error {
	if c.RedisClient == nil {
		return configuredErr
	}
	return c.RedisClient.Set(ctx, key, value, ttl).Err()
}

func (c *Cache) GetInt64(ctx context.Context, key string) (data int64, exist bool, err error) {
	if c.RedisClient == nil {
		return 0, false, configuredErr
	}
	data, err = c.RedisClient.Get(ctx, key).Int64()
	if err == redis.Nil {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	return data, true, nil
}

func (c *Cache) SetInt64(ctx context.Context, key string, value int64, ttl time.Duration) error {
	if c.RedisClient == nil {
		return configuredErr
	}
	return c.RedisClient.Set(ctx, key, value, ttl).Err()
}

func (c *Cache) Increase(ctx context.Context, key string, value int64) (data int64, err error) {
	if c.RedisClient == nil {
		return 0, configuredErr
	}
	return c.RedisClient.IncrBy(ctx, key, value).Result()
}

func (c *Cache) Decrease(ctx context.Context, key string, value int64) (data int64, err error) {
	if c.RedisClient == nil {
		return 0, configuredErr
	}
	return c.RedisClient.DecrBy(ctx, key, value).Result()
}

func (c *Cache) Del(ctx context.Context, key string) error {
	if c.RedisClient == nil {
		return configuredErr
	}
	return c.RedisClient.Del(ctx, key).Err()
}

func (c *Cache) Flush(ctx context.Context) error {
	if c.RedisClient == nil {
		return configuredErr
	}
	return c.RedisClient.FlushDB(ctx).Err()
}

func (c *Cache) ConfigFields() []plugin.ConfigField {
	return []plugin.ConfigField{
		{
			Name:        "endpoint",
			Type:        plugin.ConfigTypeInput,
			Title:       plugin.MakeTranslator(i18n.ConfigEndpointTitle),
			Description: plugin.MakeTranslator(i18n.ConfigEndpointDescription),
			Required:    true,
			UIOptions: plugin.ConfigFieldUIOptions{
				InputType: plugin.InputTypeText,
			},
			Value: c.Config.Endpoint,
		},
		{
			Name:        "username",
			Type:        plugin.ConfigTypeInput,
			Title:       plugin.MakeTranslator(i18n.ConfigUsernameTitle),
			Description: plugin.MakeTranslator(i18n.ConfigUsernameDescription),
			Required:    false,
			UIOptions: plugin.ConfigFieldUIOptions{
				InputType: plugin.InputTypeText,
			},
			Value: c.Config.Username,
		},
		{
			Name:        "password",
			Type:        plugin.ConfigTypeInput,
			Title:       plugin.MakeTranslator(i18n.ConfigPasswordTitle),
			Description: plugin.MakeTranslator(i18n.ConfigPasswordDescription),
			Required:    false,
			UIOptions: plugin.ConfigFieldUIOptions{
				InputType: plugin.InputTypePassword,
			},
			Value: c.Config.Password,
		},
		{
			Name:  "tls_enabled",
			Type:  plugin.ConfigTypeSwitch,
			Title: plugin.MakeTranslator(i18n.ConfigTLSEnabledTitle),
			Value: c.Config.TLSEnabled,
			UIOptions: plugin.ConfigFieldUIOptions{
				Label: plugin.MakeTranslator(i18n.ConfigTLSEnabledDescription),
			},
		},
		{
			Name:  "tls_skip_verify",
			Type:  plugin.ConfigTypeSwitch,
			Title: plugin.MakeTranslator(i18n.ConfigTLSSkipVerifyTitle),
			Value: c.Config.TLSSkipVerify,
			UIOptions: plugin.ConfigFieldUIOptions{
				Label: plugin.MakeTranslator(i18n.ConfigTLSSkipVerifyDescription),
			},
		},
	}
}

func (c *Cache) ConfigReceiver(config []byte) error {
	conf := &CacheConfig{}
	_ = json.Unmarshal(config, conf)
	c.Config = conf

	opts := &redis.Options{
		Addr:     conf.Endpoint,
		Username: conf.Username,
		Password: conf.Password,
	}
	if conf.TLSEnabled {
		opts.TLSConfig = &tls.Config{
			InsecureSkipVerify: conf.TLSSkipVerify,
			MinVersion:         tls.VersionTLS12,
		}
	}
	c.RedisClient = redis.NewClient(opts)
	return nil
}
