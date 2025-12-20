package comm

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/rs/zerolog/log"
)

const (
	// Time allowed to write a message to the peer
	writeWait = 10 * time.Second

	// Time allowed to read the next pong message from the peer
	pongWait = 60 * time.Second

	// Send pings to peer with this period (must be less than pongWait)
	pingPeriod = (pongWait * 9) / 10

	// Maximum message size allowed from peer
	maxMessageSize = 1024 * 1024 // 1MB

	// Reconnection settings
	initialReconnectDelay = 1 * time.Second
	maxReconnectDelay     = 30 * time.Second
	reconnectMultiplier   = 2
)

// WebSocketMessage represents a message from the server
type WebSocketMessage struct {
	Type    string          `json:"type"`
	Payload json.RawMessage `json:"payload"`
}

// MessageHandler is called when a message is received
type MessageHandler func(msg WebSocketMessage)

// WebSocketClient handles WebSocket connections with auto-reconnection
type WebSocketClient struct {
	url           string
	agentToken    string
	conn          *websocket.Conn
	mu            sync.RWMutex
	connected     bool
	handler       MessageHandler
	done          chan struct{}
	reconnectDone chan struct{}
}

// NewWebSocketClient creates a new WebSocket client
func NewWebSocketClient(url, agentToken string, handler MessageHandler) *WebSocketClient {
	return &WebSocketClient{
		url:        url,
		agentToken: agentToken,
		handler:    handler,
		done:       make(chan struct{}),
	}
}

// Connect establishes the WebSocket connection
func (c *WebSocketClient) Connect(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.connected {
		return nil
	}

	return c.connectLocked(ctx)
}

func (c *WebSocketClient) connectLocked(ctx context.Context) error {
	header := http.Header{}
	header.Set("Authorization", "Bearer "+c.agentToken)

	dialer := websocket.Dialer{
		HandshakeTimeout: 10 * time.Second,
	}

	conn, resp, err := dialer.DialContext(ctx, c.url, header)
	if err != nil {
		if resp != nil {
			return fmt.Errorf("websocket dial failed with status %d: %w", resp.StatusCode, err)
		}
		return fmt.Errorf("websocket dial failed: %w", err)
	}

	c.conn = conn
	c.connected = true
	c.reconnectDone = make(chan struct{})

	log.Info().Str("url", c.url).Msg("WebSocket connected")

	// Start read and ping loops
	go c.readLoop()
	go c.pingLoop()

	return nil
}

// StartWithReconnect starts the client with automatic reconnection
func (c *WebSocketClient) StartWithReconnect(ctx context.Context) {
	go c.reconnectLoop(ctx)
}

func (c *WebSocketClient) reconnectLoop(ctx context.Context) {
	delay := initialReconnectDelay

	for {
		select {
		case <-ctx.Done():
			return
		case <-c.done:
			return
		default:
		}

		c.mu.Lock()
		if c.connected {
			c.mu.Unlock()
			// Wait for disconnect
			select {
			case <-c.reconnectDone:
				delay = initialReconnectDelay
			case <-ctx.Done():
				return
			case <-c.done:
				return
			}
			continue
		}
		c.mu.Unlock()

		log.Info().Dur("delay", delay).Msg("Attempting WebSocket reconnection")

		err := c.Connect(ctx)
		if err != nil {
			log.Error().Err(err).Msg("WebSocket connection failed")

			// Exponential backoff
			select {
			case <-time.After(delay):
				delay = delay * time.Duration(reconnectMultiplier)
				if delay > maxReconnectDelay {
					delay = maxReconnectDelay
				}
			case <-ctx.Done():
				return
			case <-c.done:
				return
			}
			continue
		}

		delay = initialReconnectDelay
	}
}

func (c *WebSocketClient) readLoop() {
	defer func() {
		c.mu.Lock()
		c.connected = false
		if c.conn != nil {
			c.conn.Close()
		}
		close(c.reconnectDone)
		c.mu.Unlock()
	}()

	c.conn.SetReadLimit(maxMessageSize)
	c.conn.SetReadDeadline(time.Now().Add(pongWait))
	c.conn.SetPongHandler(func(string) error {
		c.conn.SetReadDeadline(time.Now().Add(pongWait))
		return nil
	})

	for {
		_, message, err := c.conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Error().Err(err).Msg("WebSocket read error")
			}
			return
		}

		var msg WebSocketMessage
		if err := json.Unmarshal(message, &msg); err != nil {
			log.Error().Err(err).Str("message", string(message)).Msg("Failed to parse WebSocket message")
			continue
		}

		if c.handler != nil {
			c.handler(msg)
		}
	}
}

func (c *WebSocketClient) pingLoop() {
	ticker := time.NewTicker(pingPeriod)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			c.mu.RLock()
			if !c.connected || c.conn == nil {
				c.mu.RUnlock()
				return
			}
			c.mu.RUnlock()

			c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				log.Error().Err(err).Msg("WebSocket ping failed")
				return
			}
		case <-c.reconnectDone:
			return
		case <-c.done:
			return
		}
	}
}

// Send sends a message through the WebSocket
func (c *WebSocketClient) Send(msg interface{}) error {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if !c.connected || c.conn == nil {
		return fmt.Errorf("websocket not connected")
	}

	data, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("failed to marshal message: %w", err)
	}

	c.conn.SetWriteDeadline(time.Now().Add(writeWait))
	return c.conn.WriteMessage(websocket.TextMessage, data)
}

// IsConnected returns whether the WebSocket is connected
func (c *WebSocketClient) IsConnected() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.connected
}

// Close closes the WebSocket connection
func (c *WebSocketClient) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	select {
	case <-c.done:
		// Already closed
	default:
		close(c.done)
	}

	if c.conn != nil {
		c.conn.SetWriteDeadline(time.Now().Add(writeWait))
		c.conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
		return c.conn.Close()
	}

	return nil
}
