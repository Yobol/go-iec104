package iec104

import (
	"crypto/tls"
	"net/url"
	"strings"
	"time"
)

const (
	DefaultConnectTimeout    = 30 * time.Second
	DefaultReconnectRetries  = 0
	DefaultReconnectInterval = 1 * time.Minute
)

func NewClientOption(server string, handler ClientHandler) (*ClientOption, error) {
	if len(server) > 0 && server[0] == ':' {
		server = "127.0.0.1" + server
	}
	if !strings.Contains(server, "://") {
		server = "tcp://" + server
	}
	remoteURL, err := url.Parse(server)
	if err != nil {
		return nil, err
	}
	return &ClientOption{
		server:         remoteURL,
		connectTimeout: DefaultConnectTimeout,
		autoReconnectRule: &AutoReconnectRule{
			retries:  DefaultReconnectRetries,
			interval: DefaultReconnectInterval,
		},
		onConnectHandler: func(c *Client) {
			_lg.Printf("connected with %s", c.conn.RemoteAddr())
			c.sendUFrame(UFrameFunctionStartDTA)
			<-c.recvChan
		},
		onDisconnectHandler: func(c *Client) {
			_lg.Printf("disconnected with %s", c.conn.RemoteAddr())
			c.sendUFrame(UFrameFunctionStopDTA)
			<-c.recvChan // receive StopDTC
		},
		handler: handler,
		tc:      nil,
	}, nil
}

type ClientOption struct {
	server            *url.URL
	connectTimeout    time.Duration
	autoReconnectRule *AutoReconnectRule

	onConnectHandler    OnConnectHandler
	onDisconnectHandler OnDisconnectHandler

	handler ClientHandler

	tc *tls.Config
}

type AutoReconnectRule struct {
	retries  int
	interval time.Duration
}

func (o *ClientOption) SetConnectTimeout(timeout time.Duration) *ClientOption {
	if timeout > 0 {
		o.connectTimeout = timeout
	}
	return o
}

func (o *ClientOption) SetAutoReconnectRule(rule *AutoReconnectRule) *ClientOption {
	if rule == nil {
		return o
	}
	if rule.retries < 0 {
		rule.retries = DefaultReconnectRetries
	}
	if rule.interval < 0 {
		rule.interval = DefaultReconnectInterval
	}
	o.autoReconnectRule = rule
	return o
}

func (o *ClientOption) SetTLS(tc *tls.Config) *ClientOption {
	o.tc = tc
	return o
}

type OnConnectHandler func(c *Client)

func (o *ClientOption) SetOnConnectHandler(handler OnConnectHandler) *ClientOption {
	if handler != nil {
		o.onConnectHandler = handler
	}
	return o
}

type OnDisconnectHandler func(c *Client)

func (o *ClientOption) SetOnDisconnectHandler(handler OnDisconnectHandler) *ClientOption {
	if handler != nil {
		o.onDisconnectHandler = handler
	}
	return o
}
