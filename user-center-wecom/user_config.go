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

package wecom

import (
	"encoding/json"
	"fmt"
	"sync"

	"github.com/apache/answer-plugins/user-center-wecom/i18n"
	"github.com/apache/answer/plugin"
	"github.com/segmentfault/pacman/log"
)

type UserConfig struct {
	InboxNotifications           bool `json:"inbox_notifications"`
	AllNewQuestions              bool `json:"all_new_questions"`
	NewQuestionsForFollowingTags bool `json:"new_questions_for_following_tags"`
}

type UserConfigCache struct {
	// key: userID value: user config
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

func (uc *UserCenter) UserConfigFields() []plugin.ConfigField {
	fields := make([]plugin.ConfigField, 0)
	// Show tip for user, if the notification service is disabled
	if !uc.Config.Notification {
		fields = append(fields, plugin.ConfigField{
			Name:        "tip",
			Type:        plugin.ConfigTypeLegend,
			Title:       plugin.MakeTranslator(i18n.ConfigTipTitle),
			Description: plugin.Translator{},
			UIOptions: plugin.ConfigFieldUIOptions{
				ClassName:      "mb-3",
				FieldClassName: "mb-0 text-danger",
			},
		})
	}
	fields = append(fields, createSwitchConfig(
		"inbox_notifications",
		i18n.UserConfigInboxNotificationsTitle,
		i18n.UserConfigInboxNotificationsLabel,
		i18n.UserConfigInboxNotificationsDescription,
	))
	fields = append(fields, createSwitchConfig(
		"all_new_questions",
		i18n.UserConfigAllNewQuestionsNotificationsTitle,
		i18n.UserConfigAllNewQuestionsNotificationsLabel,
		i18n.UserConfigAllNewQuestionsNotificationsDescription,
	))
	fields = append(fields, createSwitchConfig(
		"new_questions_for_following_tags",
		i18n.UserConfigNewQuestionsForFollowingTagsTitle,
		i18n.UserConfigNewQuestionsForFollowingTagsLabel,
		i18n.UserConfigNewQuestionsForFollowingTagsDescription,
	))
	return fields
}

func createSwitchConfig(name, title, label, desc string) plugin.ConfigField {
	return plugin.ConfigField{
		Name:        name,
		Type:        plugin.ConfigTypeSwitch,
		Title:       plugin.MakeTranslator(title),
		Description: plugin.MakeTranslator(desc),
		UIOptions: plugin.ConfigFieldUIOptions{
			Label: plugin.MakeTranslator(label),
		},
	}
}

func (uc *UserCenter) UserConfigReceiver(userID string, config []byte) error {
	log.Debugf("receive user config %s %s", userID, string(config))
	var userConfig UserConfig
	err := json.Unmarshal(config, &userConfig)
	if err != nil {
		return fmt.Errorf("unmarshal user config failed: %w", err)
	}
	uc.UserConfigCache.SetUserConfig(userID, &userConfig)
	return nil
}

func (uc *UserCenter) getUserConfig(userID string) (config *UserConfig, err error) {
	userConfig := plugin.GetPluginUserConfig(userID, uc.Info().SlugName)
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
