/*
 Reeve - Event bus

 This is a simple event bus that has glob based matching of topic subscriptions

 Copyright 2015 Evan Borgstrom

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
*/

package eventbus

import (
	"sync"

	"github.com/ryanuber/go-glob"
)

type Callback func(topic string, message string)

type Listener struct {
	topic    string
	callback Callback
}

type EventBus struct {
	listeners []*Listener
	lock      sync.Mutex
}

func NewEventBus() *EventBus {
	e := new(EventBus)
	return e
}

func (e *EventBus) Subscribe(topic string, callback Callback) *Listener {
	l := new(Listener)
	l.topic = topic
	l.callback = callback

	e.lock.Lock()
	defer e.lock.Unlock()

	e.listeners = append(e.listeners, l)

	return l
}

func (e *EventBus) Unsubscribe(listener *Listener) bool {
	e.lock.Lock()
	defer e.lock.Unlock()

	for i, l := range e.listeners {
		if l == listener {
			// https://github.com/golang/go/wiki/SliceTricks
			copy(e.listeners[i:], e.listeners[i+1:])
			e.listeners[len(e.listeners)-1] = nil
			e.listeners = e.listeners[:len(e.listeners)-1]
			return true
		}
	}
	return false
}

func (e *EventBus) Publish(topic string, message string) {
	for _, l := range e.listeners {
		if glob.Glob(l.topic, topic) {
			go l.callback(topic, message)
		}
	}
}
