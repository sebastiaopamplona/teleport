/*
Copyright 2021 Gravitational, Inc.

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

package streamproto

import (
	"io"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/utils"
	"github.com/gravitational/trace"
	"k8s.io/client-go/tools/remotecommand"
)

type metaMessage struct {
	Resize          *remotecommand.TerminalSize `json:"resize,omitempty"`
	ForceTerminate  bool                        `json:"force_terminate,omitempty"`
	ClientHandshake *ClientHandshake            `json:"client_handshake,omitempty"`
	ServerHandshake *ServerHandshake            `json:"server_handshake,omitempty"`
}

type ClientHandshake struct {
	Mode types.SessionParticipantMode `json:"mode"`
}

type ServerHandshake struct {
	MFARequired bool `json:"mfa_required"`
}

type SessionStream struct {
	conn           *websocket.Conn
	in             chan []byte
	currentIn      []byte
	resizeQueue    chan *remotecommand.TerminalSize
	forceTerminate chan struct{}
	writeSync      sync.Mutex
	CloseC         chan struct{}
	closedC        sync.Once
	closed         bool
	MFARequired    bool
	Mode           types.SessionParticipantMode
}

func NewSessionStream(conn *websocket.Conn, handshake interface{}) (*SessionStream, error) {
	s := &SessionStream{
		conn:           conn,
		in:             make(chan []byte),
		CloseC:         make(chan struct{}),
		resizeQueue:    make(chan *remotecommand.TerminalSize, 1),
		forceTerminate: make(chan struct{}),
	}

	clientHandshake, isClient := handshake.(ClientHandshake)
	serverHandshake, ok := handshake.(ServerHandshake)

	if !isClient && !ok {
		return nil, trace.BadParameter("handshake must be either client or server handshake")
	}

	if isClient {
		ty, data, err := conn.ReadMessage()
		if err != nil {
			return nil, trace.Wrap(err)
		}

		if ty != websocket.TextMessage {
			return nil, trace.Errorf("expected websocket control message, got %v", ty)
		}

		var msg metaMessage
		if err := utils.FastUnmarshal(data, &msg); err != nil {
			return nil, trace.Wrap(err)
		}

		if msg.ServerHandshake == nil {
			return nil, trace.Errorf("expected websocket server handshake, got %v", msg)
		}

		s.MFARequired = msg.ServerHandshake.MFARequired
		handshakeMsg := metaMessage{ClientHandshake: &clientHandshake}
		dataClientHandshake, err := utils.FastMarshal(handshakeMsg)
		if err != nil {
			return nil, trace.Wrap(err)
		}

		if err := conn.WriteMessage(websocket.TextMessage, dataClientHandshake); err != nil {
			return nil, trace.Wrap(err)
		}
	} else {
		handshakeMsg := metaMessage{ServerHandshake: &serverHandshake}
		dataServerHandshake, err := utils.FastMarshal(handshakeMsg)
		if err != nil {
			return nil, trace.Wrap(err)
		}

		if err := conn.WriteMessage(websocket.TextMessage, dataServerHandshake); err != nil {
			return nil, trace.Wrap(err)
		}

		ty, data, err := conn.ReadMessage()
		if err != nil {
			return nil, trace.Wrap(err)
		}

		if ty != websocket.TextMessage {
			return nil, trace.Errorf("expected websocket control message, got %v", ty)
		}

		var msg metaMessage
		if err := utils.FastUnmarshal(data, &msg); err != nil {
			return nil, trace.Wrap(err)
		}

		if msg.ClientHandshake == nil {
			return nil, trace.Errorf("expected websocket client handshake, got %v", msg)
		}

		s.Mode = msg.ClientHandshake.Mode
	}

	go s.readTask()
	return s, nil
}

func (s *SessionStream) readTask() {
	for {
		terminated := false
		defer s.closedC.Do(func() { close(s.CloseC) })
		ty, data, err := s.conn.ReadMessage()
		if err != nil {
			return
		}

		if ty == websocket.BinaryMessage {
			s.in <- data
		}

		if ty == websocket.TextMessage {
			var msg metaMessage
			if err := utils.FastUnmarshal(data, &msg); err != nil {
				return
			}

			if msg.Resize != nil {
				s.resizeQueue <- msg.Resize
			}

			if msg.ForceTerminate && !terminated {
				terminated = true
				close(s.forceTerminate)
			}
		}

		if ty == websocket.CloseMessage {
			s.conn.Close()
			s.closed = true
			return
		}
	}
}

func (s *SessionStream) Read(p []byte) (int, error) {
	if len(s.currentIn) == 0 {
		select {
		case s.currentIn = <-s.in:
		case <-s.CloseC:
			return 0, io.EOF
		}
	}

	n := copy(p, s.currentIn)
	s.currentIn = s.currentIn[n:]
	return n, nil
}

func (s *SessionStream) Write(data []byte) (int, error) {
	s.writeSync.Lock()
	defer s.writeSync.Unlock()

	return len(data), s.conn.WriteMessage(websocket.BinaryMessage, data)
}

func (s *SessionStream) Resize(size *remotecommand.TerminalSize) error {
	msg := metaMessage{Resize: size}
	json, err := utils.FastMarshal(msg)
	if err != nil {
		return trace.Wrap(err)
	}

	s.writeSync.Lock()
	defer s.writeSync.Unlock()

	return trace.Wrap(s.conn.WriteMessage(websocket.TextMessage, json))
}

func (s *SessionStream) ResizeQueue() chan *remotecommand.TerminalSize {
	return s.resizeQueue
}

func (s *SessionStream) ForceTerminate() chan struct{} {
	return s.forceTerminate
}

func (s *SessionStream) DoForceTerminate() error {
	msg := metaMessage{ForceTerminate: true}
	json, err := utils.FastMarshal(msg)
	if err != nil {
		return trace.Wrap(err)
	}

	s.writeSync.Lock()
	defer s.writeSync.Unlock()

	return trace.Wrap(s.conn.WriteMessage(websocket.TextMessage, json))
}

func (s *SessionStream) WaitOnClose() {
	<-s.CloseC
}

func (s *SessionStream) Close() error {
	if !s.closed {
		s.conn.WriteMessage(websocket.CloseMessage, []byte{})

		select {
		case <-s.CloseC:
		case <-time.After(time.Second * 5):
		}
	}

	return nil
}
