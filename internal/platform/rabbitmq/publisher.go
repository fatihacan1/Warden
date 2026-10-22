// Package rabbitmq publishes domain events to a RabbitMQ topic exchange with
// publisher confirms and automatic reconnection.
package rabbitmq

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	amqp "github.com/rabbitmq/amqp091-go"
)

// Publisher publishes persistent messages and waits for broker confirmation,
// so an event is only marked delivered in the outbox once RabbitMQ owns it.
type Publisher struct {
	url      string
	exchange string
	log      *slog.Logger

	mu   sync.Mutex
	conn *amqp.Connection
	ch   *amqp.Channel
}

func NewPublisher(url, exchange string, log *slog.Logger) *Publisher {
	return &Publisher{url: url, exchange: exchange, log: log}
}

// Connect establishes the connection eagerly (optional; Publish reconnects
// lazily).
func (p *Publisher) Connect() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	_, err := p.channelLocked()
	return err
}

func (p *Publisher) channelLocked() (*amqp.Channel, error) {
	if p.ch != nil && !p.ch.IsClosed() && p.conn != nil && !p.conn.IsClosed() {
		return p.ch, nil
	}
	p.closeLocked()
	conn, err := amqp.DialConfig(p.url, amqp.Config{
		Heartbeat:  10 * time.Second,
		Locale:     "en_US",
		Properties: amqp.Table{"connection_name": "warden"},
		Dial:       amqp.DefaultDial(5 * time.Second),
	})
	if err != nil {
		return nil, fmt.Errorf("rabbitmq: dial: %w", err)
	}
	ch, err := conn.Channel()
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("rabbitmq: channel: %w", err)
	}
	if err := ch.Confirm(false); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("rabbitmq: confirm mode: %w", err)
	}
	if err := ch.ExchangeDeclare(p.exchange, amqp.ExchangeTopic, true, false, false, false, nil); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("rabbitmq: declare exchange: %w", err)
	}
	p.conn, p.ch = conn, ch
	p.log.Info("rabbitmq connected", "exchange", p.exchange)
	return ch, nil
}

// Publish sends body with routing key = topic (e.g. "user.created").
func (p *Publisher) Publish(ctx context.Context, topic, messageID string, body []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	ch, err := p.channelLocked()
	if err != nil {
		return err
	}
	dc, err := ch.PublishWithDeferredConfirmWithContext(ctx, p.exchange, topic, false, false, amqp.Publishing{
		ContentType:  "application/json",
		DeliveryMode: amqp.Persistent,
		MessageId:    messageID,
		Timestamp:    time.Now().UTC(),
		Type:         topic,
		AppId:        "warden",
		Body:         body,
	})
	if err != nil {
		p.closeLocked()
		return fmt.Errorf("rabbitmq: publish: %w", err)
	}
	ok, err := dc.WaitContext(ctx)
	if err != nil {
		p.closeLocked()
		return fmt.Errorf("rabbitmq: confirm: %w", err)
	}
	if !ok {
		return errors.New("rabbitmq: message nacked by broker")
	}
	return nil
}

// Ping reports whether a channel can be opened.
func (p *Publisher) Ping(context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	_, err := p.channelLocked()
	return err
}

func (p *Publisher) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closeLocked()
	return nil
}

func (p *Publisher) closeLocked() {
	if p.ch != nil {
		_ = p.ch.Close()
		p.ch = nil
	}
	if p.conn != nil {
		_ = p.conn.Close()
		p.conn = nil
	}
}
