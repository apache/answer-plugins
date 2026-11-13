/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0.
 */

package dingtalk

import (
	"fmt"
	"sync"
	"testing"
)

func TestUserConfigCacheConcurrentNewQuestionSubscribers(t *testing.T) {
	cache := NewUserConfigCache()
	const workers, iterations = 8, 500
	start := make(chan struct{})
	var wg sync.WaitGroup
	for worker := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for i := range iterations {
				cache.SetUserConfig(fmt.Sprintf("writer-%d-user-%d", worker, i%32), &UserConfig{AllNewQuestions: i%2 == 0})
			}
		}()
	}
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for range iterations {
				_ = cache.NewQuestionSubscriberIDs()
			}
		}()
	}
	close(start)
	wg.Wait()

	cache.SetUserConfig("subscriber", &UserConfig{AllNewQuestions: true})
	for _, userID := range cache.NewQuestionSubscriberIDs() {
		if userID == "subscriber" {
			return
		}
	}
	t.Fatal("subscriber missing from snapshot")
}
