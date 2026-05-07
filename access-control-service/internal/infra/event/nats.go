package event

import (
	"context"
	"encoding/json"
	"github.com/nats-io/nats.go"
)

type Publisher struct{ nc *nats.Conn }

func NewPublisher(url string) (*Publisher, error) {
	nc, err := nats.Connect(url)
	if err != nil {
		return nil, err
	}
	return &Publisher{nc: nc}, nil
}
func (p *Publisher) Publish(ctx context.Context, subject string, payload any) error {
	b, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	return p.nc.Publish(subject, b)
}
func (p *Publisher) Close() {
	if p != nil && p.nc != nil {
		p.nc.Close()
	}
}
