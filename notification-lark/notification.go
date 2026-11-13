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
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"strings"

	lark_i18n "github.com/apache/answer-plugins/notification-lark/i18n"
	"github.com/apache/answer-plugins/util"
	"github.com/apache/answer/plugin"

	"github.com/segmentfault/pacman/i18n"
	"github.com/segmentfault/pacman/log"

	lark "github.com/larksuite/oapi-sdk-go/v3"
	"github.com/larksuite/oapi-sdk-go/v3/event/dispatcher"
	larkApplication "github.com/larksuite/oapi-sdk-go/v3/service/application/v6"
	larkIM "github.com/larksuite/oapi-sdk-go/v3/service/im/v1"
	larkWebSocket "github.com/larksuite/oapi-sdk-go/v3/ws"
)

//go:embed  info.yaml
var Info embed.FS

type LarkClient struct {
	ws   *larkWebSocket.Client
	http *lark.Client
}

type Notification struct {
	info            *util.Info
	config          *NotificationConfig
	client          *LarkClient
	userConfigCache *UserConfigCache
}

const (
	LarkBindAccountMenuEventKey = "10001"
	NotificationTypeInteractive = "interactive"
	MsgTypeText                 = "text"
	ReceiveIdTypeOpenId         = "open_id"
)

var (
	TagColor = []string{"neutral", "blue", "turquoise", "lime", "orange", "violet", "indigo", "wathet", "green", "yellow", "red", "purple", "carmine"}
)

func init() {
	plugin.Register(&Notification{
		userConfigCache: NewUserConfigCache(),
	})
}

func (n Notification) Info() plugin.Info {
	if n.info == nil {
		info := &util.Info{}
		info.GetInfo(Info)
		n.info = info
	}

	return plugin.Info{
		Name:        plugin.MakeTranslator(lark_i18n.InfoName),
		SlugName:    n.info.SlugName,
		Description: plugin.MakeTranslator(lark_i18n.InfoDescription),
		Author:      n.info.Author,
		Version:     n.info.Version,
		Link:        n.info.Link,
	}
}

func renderTag(tags []string) string {
	var builder strings.Builder
	for _, tag := range tags {
		idx := RandomInt(0, int64(len(TagColor)))
		builder.WriteString(fmt.Sprintf(`<text_tag color='%s'> %s </text_tag>`, TagColor[idx], tag))
	}
	return builder.String()
}

func renderNotification(msg plugin.NotificationMessage) string {
	lang := i18n.Language(msg.ReceiverLang)
	switch msg.Type {
	case plugin.NotificationUpdateQuestion:
		return plugin.TranslateWithData(lang, lark_i18n.TplUpdateQuestion, msg)
	case plugin.NotificationAnswerTheQuestion:
		return plugin.TranslateWithData(lang, lark_i18n.TplAnswerTheQuestion, msg)
	case plugin.NotificationUpdateAnswer:
		return plugin.TranslateWithData(lang, lark_i18n.TplUpdateAnswer, msg)
	case plugin.NotificationAcceptAnswer:
		return plugin.TranslateWithData(lang, lark_i18n.TplAcceptAnswer, msg)
	case plugin.NotificationCommentQuestion:
		return plugin.TranslateWithData(lang, lark_i18n.TplCommentQuestion, msg)
	case plugin.NotificationCommentAnswer:
		return plugin.TranslateWithData(lang, lark_i18n.TplCommentAnswer, msg)
	case plugin.NotificationReplyToYou:
		return plugin.TranslateWithData(lang, lark_i18n.TplReplyToYou, msg)
	case plugin.NotificationMentionYou:
		return plugin.TranslateWithData(lang, lark_i18n.TplMentionYou, msg)
	case plugin.NotificationInvitedYouToAnswer:
		return plugin.TranslateWithData(lang, lark_i18n.TplInvitedYouToAnswer, msg)
	case plugin.NotificationNewQuestion, plugin.NotificationNewQuestionFollowedTag:
		msg.QuestionTags = renderTag(strings.Split(msg.QuestionTags, ","))
		return plugin.TranslateWithData(lang, lark_i18n.TplNewQuestion, msg)
	}
	return ""
}

func makeCardMsg(args plugin.NotificationMessage) Card {
	action := &Action{
		Tag: "action",
		Actions: []*Button{
			{
				Width: "fill",
				Text: &Text{
					Tag:     "plain_text",
					Content: "查看详情",
					Icon: &Icon{
						Tag:   "standard_icon",
						Token: "link-copy_outlined",
					},
				},
				Behaviors: []Behavior{
					{
						Type:       "open_url",
						DefaultURL: args.QuestionUrl,
					},
				},
			},
		},
	}

	columnSet := func(content string) ColumnSet {
		return ColumnSet{
			Show: &Show{
				Tag:      "column_set",
				FlexMode: "flex_mode",
				Columns: []Column{
					{
						Elements: []Element{
							{
								PlainText: &PlainText{
									Tag: "div",
									Text: &Text{
										Tag:     "lark_md",
										Content: content,
									},
								},
							},
						},
					},
				},
			},
			Action: action,
		}
	}

	card := Card{
		Config: &Config{
			WidthMode:            "compact",
			UseCustomTranslation: PtrBool(true),
			EnableForward:        PtrBool(false),
		},
		Header: &Header{
			Title: &Text{
				Tag: "plain_text",
				I18n: &I18n{
					ZhCn: "新通知",
					EnUs: "New Notification",
				},
			},
			UdIcon: &Icon{
				Tag:   "icon",
				Token: "bell_outlined",
				Color: "blue",
			},
			Template: ThemeGreen,
		},
		I18nElements: &I18nElements{
			ZhCn: []ColumnSet{},
			EnUs: []ColumnSet{},
		},
	}

	args.ReceiverLang = string(i18n.LanguageChinese)
	card.I18nElements.ZhCn = append(card.I18nElements.ZhCn, columnSet(renderNotification(args)))
	args.ReceiverLang = string(i18n.LanguageEnglish)
	card.I18nElements.EnUs = append(card.I18nElements.EnUs, columnSet(renderNotification(args)))
	return card
}

// GetNewQuestionSubscribers returns the subscribers of the new question notification
func (n *Notification) GetNewQuestionSubscribers() (userIDs []string) {
	return n.userConfigCache.NewQuestionSubscriberIDs()
}

// Notify sends a notification to the user
func (n *Notification) Notify(msg plugin.NotificationMessage) {
	ctx := context.TODO()
	log.Debugf("Attempting to send notification to user %s: %+v", msg.ReceiverUserID, msg)

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
	if userConfig.OpenId == "" {
		log.Debugf("user %s not set the open id", msg.ReceiverUserID)
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

	cardMsg := makeCardMsg(msg)
	notificationMsg, err := json.Marshal(cardMsg)
	if err != nil {
		log.Errorf("marshal notification message failed: %v", err)
		return
	}
	log.Debugf("card message: %s", notificationMsg)

	if len(notificationMsg) == 0 {
		log.Debugf("this type of notification will be drop, the type is %s", msg.Type)
		return
	}
	req := larkIM.NewCreateMessageReqBuilder().
		ReceiveIdType(ReceiveIdTypeOpenId).
		Body(larkIM.NewCreateMessageReqBodyBuilder().
			ReceiveId(userConfig.OpenId).
			MsgType(NotificationTypeInteractive).
			Content(string(notificationMsg)).
			Build()).
		Build()

	resp, err := n.client.http.Im.Message.Create(ctx, req)
	if err != nil || !resp.Success() {
		log.Errorf("Failed to send message to user %s: %v", userConfig.OpenId, err)
	}
}

// LarkWsEventMenuClick is the event handler for the menu click event
func (n *Notification) LarkWsEventMenuClick(ctx context.Context, event *larkApplication.P2BotMenuV6) error {
	switch *event.Event.EventKey {
	case LarkBindAccountMenuEventKey:
		contentData, _ := json.Marshal(map[string]interface{}{
			"text": *event.Event.Operator.OperatorId.OpenId,
		})

		req := larkIM.NewCreateMessageReqBuilder().
			ReceiveIdType(ReceiveIdTypeOpenId).
			Body(larkIM.NewCreateMessageReqBodyBuilder().
				ReceiveId(*event.Event.Operator.OperatorId.OpenId).
				MsgType(MsgTypeText).
				Content(string(contentData)).
				Build()).
			Build()

		resp, err := n.client.http.Im.Message.Create(context.Background(), req)
		if err != nil || !resp.Success() {
			fmt.Printf("Failed to send message: %v\n", err)
			return nil
		}
	}

	return nil
}

func (n *Notification) LarkWsEventHub() *dispatcher.EventDispatcher {
	return dispatcher.NewEventDispatcher(n.config.VerificationToken, n.config.EventEncryptKey).
		OnP2BotMenuV6(n.LarkWsEventMenuClick)
}

func (n *LarkClient) Start() error {
	// TODO: wait feishu sdk fix the cancel not work issue
	// https://github.com/larksuite/oapi-sdk-go/issues/141
	// ctx, cancel := context.WithCancel(context.TODO())
	n.ws.Start(context.TODO())
	return nil
}
