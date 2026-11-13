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

package dingtalk

import (
	"embed"
	"strings"

	dingtalkI18n "github.com/apache/answer-plugins/notification-dingtalk/i18n"
	"github.com/apache/answer-plugins/util"
	"github.com/apache/answer/plugin"
	"github.com/go-resty/resty/v2"
	"github.com/segmentfault/pacman/i18n"
	"github.com/segmentfault/pacman/log"
)

//go:embed  info.yaml
var Info embed.FS

type Notification struct {
	Config          *NotificationConfig
	UserConfigCache *UserConfigCache
}

func init() {
	uc := &Notification{
		Config:          &NotificationConfig{},
		UserConfigCache: NewUserConfigCache(),
	}
	plugin.Register(uc)
}

func (n *Notification) Info() plugin.Info {
	info := &util.Info{}
	info.GetInfo(Info)

	return plugin.Info{
		Name:        plugin.MakeTranslator(dingtalkI18n.InfoName),
		SlugName:    info.SlugName,
		Description: plugin.MakeTranslator(dingtalkI18n.InfoDescription),
		Author:      info.Author,
		Version:     info.Version,
		Link:        info.Link,
	}
}

// GetNewQuestionSubscribers returns the subscribers of the new question notification
func (n *Notification) GetNewQuestionSubscribers() (userIDs []string) {
	return n.UserConfigCache.NewQuestionSubscriberIDs()
}

// Notify sends a notification to the user
func (n *Notification) Notify(msg plugin.NotificationMessage) {
	log.Debugf("try to send notification %+v", msg)

	if !n.Config.Notification {
		return
	}

	// get user config
	userConfig, err := n.getUserConfig(msg.ReceiverUserID)
	if err != nil {
		log.Errorf("get user config failed: %v", err)
		return
	}
	if userConfig == nil {
		log.Debugf("user %s has no config", msg.ReceiverUserID)
		return
	}

	// check if the notification is enabled
	switch msg.Type {
	case plugin.NotificationNewQuestion:
		if !userConfig.AllNewQuestions {
			log.Debugf("user %s not config the new question", msg.ReceiverUserID)
			return
		}
	case plugin.NotificationNewQuestionFollowedTag:
		if !userConfig.NewQuestionsForFollowingTags {
			log.Debugf("user %s not config the new question followed tag", msg.ReceiverUserID)
			return
		}
	default:
		if !userConfig.InboxNotifications {
			log.Debugf("user %s not config the inbox notification", msg.ReceiverUserID)
			return
		}
	}

	log.Debugf("user %s config the notification", msg.ReceiverUserID)

	if len(userConfig.WebhookURL) == 0 {
		log.Errorf("user %s has no webhook url", msg.ReceiverUserID)
		return
	}

	notificationMsg, notificationTitle := renderNotification(msg)
	// no need to send empty message
	if len(notificationMsg) == 0 {
		log.Debugf("this type of notification will be drop, the type is %s", msg.Type)
		return
	}

	// Create a Resty Client
	client := resty.New()
	resp, err := client.R().
		SetHeader("Content-Type", "application/json").
		SetBody(NewWebhookReq(notificationMsg, notificationTitle)).
		Post(userConfig.WebhookURL)

	if err != nil {
		log.Errorf("send message failed: %v %v", err, resp)
	} else {
		log.Infof("send message to %s success, resp: %s", msg.ReceiverUserID, resp.String())
	}
}

func renderNotification(msg plugin.NotificationMessage) (string, string) {
	lang := i18n.Language(msg.ReceiverLang)
	switch msg.Type {
	case plugin.NotificationUpdateQuestion:
		return plugin.TranslateWithData(lang, dingtalkI18n.TplUpdateQuestion, msg), plugin.TranslateWithData(lang, dingtalkI18n.TplUpdateQuestionTitle, nil)
	case plugin.NotificationAnswerTheQuestion:
		return plugin.TranslateWithData(lang, dingtalkI18n.TplAnswerTheQuestion, msg), plugin.TranslateWithData(lang, dingtalkI18n.TplAnswerTheQuestionTitle, nil)
	case plugin.NotificationUpdateAnswer:
		return plugin.TranslateWithData(lang, dingtalkI18n.TplUpdateAnswer, msg), plugin.TranslateWithData(lang, dingtalkI18n.TplUpdateAnswerTitle, nil)
	case plugin.NotificationAcceptAnswer:
		return plugin.TranslateWithData(lang, dingtalkI18n.TplAcceptAnswer, msg), plugin.TranslateWithData(lang, dingtalkI18n.TplAcceptAnswerTitle, nil)
	case plugin.NotificationCommentQuestion:
		return plugin.TranslateWithData(lang, dingtalkI18n.TplCommentQuestion, msg), plugin.TranslateWithData(lang, dingtalkI18n.TplCommentQuestionTitle, nil)
	case plugin.NotificationCommentAnswer:
		return plugin.TranslateWithData(lang, dingtalkI18n.TplCommentAnswer, msg), plugin.TranslateWithData(lang, dingtalkI18n.TplCommentAnswerTitle, nil)
	case plugin.NotificationReplyToYou:
		return plugin.TranslateWithData(lang, dingtalkI18n.TplReplyToYou, msg), plugin.TranslateWithData(lang, dingtalkI18n.TplReplyToYouTitle, nil)
	case plugin.NotificationMentionYou:
		return plugin.TranslateWithData(lang, dingtalkI18n.TplMentionYou, msg), plugin.TranslateWithData(lang, dingtalkI18n.TplMentionYouTitle, nil)
	case plugin.NotificationInvitedYouToAnswer:
		return plugin.TranslateWithData(lang, dingtalkI18n.TplInvitedYouToAnswer, msg), plugin.TranslateWithData(lang, dingtalkI18n.TplInvitedYouToAnswerTitle, nil)
	case plugin.NotificationNewQuestion, plugin.NotificationNewQuestionFollowedTag:
		msg.QuestionTags = strings.Join(strings.Split(msg.QuestionTags, ","), ", ")
		return plugin.TranslateWithData(lang, dingtalkI18n.TplNewQuestion, msg), plugin.TranslateWithData(lang, dingtalkI18n.TplNewQuestionTitle, nil)
	}
	return "", ""
}
