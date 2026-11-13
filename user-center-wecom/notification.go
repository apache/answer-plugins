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
	"strings"

	wecomI18n "github.com/apache/answer-plugins/user-center-wecom/i18n"
	"github.com/apache/answer/plugin"
	"github.com/segmentfault/pacman/i18n"
	"github.com/segmentfault/pacman/log"
	"github.com/silenceper/wechat/v2/work/message"
)

// GetNewQuestionSubscribers returns the subscribers of the new question notification
func (uc *UserCenter) GetNewQuestionSubscribers() (userIDs []string) {
	return uc.UserConfigCache.NewQuestionSubscriberIDs()
}

// Notify sends a notification to the user
func (uc *UserCenter) Notify(msg plugin.NotificationMessage) {
	log.Debugf("try to send notification %+v", msg)

	if !uc.Config.Notification {
		return
	}

	// get user config
	userConfig, err := uc.getUserConfig(msg.ReceiverUserID)
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

	log.Debugf("user %s config the notification", msg.ReceiverExternalID)

	userDetail := uc.Company.UserDetailInfoMapping[msg.ReceiverExternalID]
	if userDetail == nil {
		log.Infof("user [%s] not found", msg.ReceiverExternalID)
		return
	}

	notificationMsg := renderNotification(msg)
	// no need to send empty message
	if len(notificationMsg) == 0 {
		log.Debugf("this type of notification will be drop, the type is %s", msg.Type)
		return
	}
	resp, err := uc.Company.Work.GetMessage().SendText(message.SendTextRequest{
		SendRequestCommon: &message.SendRequestCommon{
			ToUser:  userDetail.Userid,
			MsgType: "text",
			AgentID: uc.Config.AgentID,
		},
		Text: message.TextField{
			Content: notificationMsg,
		},
	})
	if err != nil {
		log.Errorf("send message failed: %v %v", err, resp)
	} else {
		log.Infof("send message to %s success", msg.ReceiverExternalID)
	}
}

func renderNotification(msg plugin.NotificationMessage) string {
	lang := i18n.Language(msg.ReceiverLang)
	switch msg.Type {
	case plugin.NotificationUpdateQuestion:
		return plugin.TranslateWithData(lang, wecomI18n.TplUpdateQuestion, msg)
	case plugin.NotificationAnswerTheQuestion:
		return plugin.TranslateWithData(lang, wecomI18n.TplAnswerTheQuestion, msg)
	case plugin.NotificationUpdateAnswer:
		return plugin.TranslateWithData(lang, wecomI18n.TplUpdateAnswer, msg)
	case plugin.NotificationAcceptAnswer:
		return plugin.TranslateWithData(lang, wecomI18n.TplAcceptAnswer, msg)
	case plugin.NotificationCommentQuestion:
		return plugin.TranslateWithData(lang, wecomI18n.TplCommentQuestion, msg)
	case plugin.NotificationCommentAnswer:
		return plugin.TranslateWithData(lang, wecomI18n.TplCommentAnswer, msg)
	case plugin.NotificationReplyToYou:
		return plugin.TranslateWithData(lang, wecomI18n.TplReplyToYou, msg)
	case plugin.NotificationMentionYou:
		return plugin.TranslateWithData(lang, wecomI18n.TplMentionYou, msg)
	case plugin.NotificationInvitedYouToAnswer:
		return plugin.TranslateWithData(lang, wecomI18n.TplInvitedYouToAnswer, msg)
	case plugin.NotificationNewQuestion, plugin.NotificationNewQuestionFollowedTag:
		msg.QuestionTags = strings.Join(strings.Split(msg.QuestionTags, ","), ", ")
		return plugin.TranslateWithData(lang, wecomI18n.TplNewQuestion, msg)
	}
	return ""
}
