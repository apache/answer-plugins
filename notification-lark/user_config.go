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

package lark

import (
	"encoding/json"
	"fmt"
	"sync"

	"github.com/apache/answer-plugins/notification-lark/i18n"
	"github.com/apache/answer/plugin"

	"github.com/segmentfault/pacman/log"
)

type UserConfig struct {
	OpenId                       string `json:"open_id"`
	InboxNotifications           bool   `json:"inbox_notifications"`
	AllNewQuestions              bool   `json:"all_new_questions"`
	NewQuestionsForFollowingTags bool   `json:"new_questions_for_following_tags"`
}

type UserConfigCache struct {
	userConfigMapping map[string]*UserConfig
	sync.RWMutex
}

func NewUserConfigCache() *UserConfigCache {
	ucc := &UserConfigCache{
		userConfigMapping: make(map[string]*UserConfig),
	}
	return ucc
}

func (ucc *UserConfigCache) SetUserConfig(userID string, config *UserConfig) {
	ucc.Lock()
	defer ucc.Unlock()
	ucc.userConfigMapping[userID] = config
}

func (ucc *UserConfigCache) NewQuestionSubscriberIDs() []string {
	ucc.RLock()
	defer ucc.RUnlock()

	userIDs := make([]string, 0)
	for userID, conf := range ucc.userConfigMapping {
		if conf.AllNewQuestions {
			userIDs = append(userIDs, userID)
		}
	}
	return userIDs
}

func (n *Notification) UserConfigFields() []plugin.ConfigField {
	return []plugin.ConfigField{
		{
			Name:        "open_id",
			Type:        plugin.ConfigTypeInput,
			Title:       plugin.MakeTranslator(i18n.UserConfigOpenIdTitle),
			Description: plugin.MakeTranslator(i18n.UserConfigOpenIdDescription),
			UIOptions: plugin.ConfigFieldUIOptions{
				InputType: plugin.InputTypeText,
			},
		},
		{
			Name:        "inbox_notifications",
			Type:        plugin.ConfigTypeSwitch,
			Title:       plugin.MakeTranslator(i18n.UserConfigInboxNotificationsTitle),
			Description: plugin.MakeTranslator(i18n.UserConfigInboxNotificationsDescription),
			UIOptions: plugin.ConfigFieldUIOptions{
				Label: plugin.MakeTranslator(i18n.UserConfigInboxNotificationsLabel),
			},
		},
		{
			Name:        "all_new_questions",
			Type:        plugin.ConfigTypeSwitch,
			Title:       plugin.MakeTranslator(i18n.UserConfigAllNewQuestionsTitle),
			Description: plugin.MakeTranslator(i18n.UserConfigAllNewQuestionsDescription),
			UIOptions: plugin.ConfigFieldUIOptions{
				Label: plugin.MakeTranslator(i18n.UserConfigAllNewQuestionsLabel),
			},
		},
		{
			Name:        "new_questions_for_following_tags",
			Type:        plugin.ConfigTypeSwitch,
			Title:       plugin.MakeTranslator(i18n.UserConfigNewQuestionsForFollowingTagsTitle),
			Description: plugin.MakeTranslator(i18n.UserConfigNewQuestionsForFollowingTagsDescription),
			UIOptions: plugin.ConfigFieldUIOptions{
				Label: plugin.MakeTranslator(i18n.UserConfigNewQuestionsForFollowingTagsLabel),
			},
		},
	}
}

func (n *Notification) UserConfigReceiver(userID string, config []byte) error {
	log.Debugf("receive user config %s %s", userID, string(config))
	var userConfig UserConfig
	err := json.Unmarshal(config, &userConfig)
	if err != nil {
		return fmt.Errorf("unmarshal user config failed: %w", err)
	}
	n.userConfigCache.SetUserConfig(userID, &userConfig)
	return nil
}

func (n *Notification) getUserConfig(userID string) (config *UserConfig, err error) {
	userConfig := plugin.GetPluginUserConfig(userID, n.Info().SlugName)
	if len(userConfig) == 0 {
		return nil, nil
	}
	config = &UserConfig{}
	err = json.Unmarshal(userConfig, config)
	if err != nil {
		return nil, fmt.Errorf("unmarshal user config failed: %w", err)
	}
	return config, nil
}
