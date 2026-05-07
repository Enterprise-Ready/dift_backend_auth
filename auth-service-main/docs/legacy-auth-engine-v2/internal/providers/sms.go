//go:build legacy
// +build legacy

package providers

import (
	"context"
	"fmt"
	"strings"

	"github.com/enterprise/auth-engine/internal/config"
	"github.com/enterprise/auth-engine/internal/models"
	"github.com/twilio/twilio-go"
	twilioApi "github.com/twilio/twilio-go/rest/api/v2010"
)

// ─── Interface ────────────────────────────────────────────────────────────────

type SMSProvider interface {
	Send(ctx context.Context, to, message string) error
}

// ─── Factory ──────────────────────────────────────────────────────────────────

func NewSMSProvider(cfg *config.SMSConfig) (SMSProvider, error) {
	switch cfg.Provider {
	case "twilio":
		return NewTwilioProvider(cfg), nil
	case "aws_sns":
		return NewSNSProvider(cfg), nil
	case "vonage":
		return NewVonageProvider(cfg), nil
	default:
		return nil, fmt.Errorf("unknown sms provider: %s", cfg.Provider)
	}
}

// ─── SMS Notifier Adapter ─────────────────────────────────────────────────────

type SMSNotifier struct {
	provider SMSProvider
}

func NewSMSNotifier(provider SMSProvider) *SMSNotifier {
	return &SMSNotifier{provider: provider}
}

func (n *SMSNotifier) SendSMSOTP(ctx context.Context, to, code string, purpose models.OTPPurpose) error {
	msg := buildSMSMessage(code, purpose)
	return n.provider.Send(ctx, to, msg)
}

// ─── Twilio ───────────────────────────────────────────────────────────────────

type TwilioProvider struct {
	client     *twilio.RestClient
	fromNumber string
}

func NewTwilioProvider(cfg *config.SMSConfig) *TwilioProvider {
	client := twilio.NewRestClientWithParams(twilio.ClientParams{
		Username: cfg.TwilioSID,
		Password: cfg.TwilioAuthToken,
	})
	return &TwilioProvider{client: client, fromNumber: cfg.TwilioFromNumber}
}

func (p *TwilioProvider) Send(ctx context.Context, to, message string) error {
	params := &twilioApi.CreateMessageParams{}
	params.SetTo(to)
	params.SetFrom(p.fromNumber)
	params.SetBody(message)

	_, err := p.client.Api.CreateMessage(params)
	if err != nil {
		return fmt.Errorf("twilio send sms: %w", err)
	}
	return nil
}

// ─── AWS SNS ──────────────────────────────────────────────────────────────────

type SNSProvider struct {
	cfg *config.SMSConfig
}

func NewSNSProvider(cfg *config.SMSConfig) *SNSProvider {
	return &SNSProvider{cfg: cfg}
}

func (p *SNSProvider) Send(ctx context.Context, to, message string) error {
	// Production: use github.com/aws/aws-sdk-go-v2/service/sns
	// snsClient.Publish(ctx, &sns.PublishInput{
	//   Message:     aws.String(message),
	//   PhoneNumber: aws.String(to),
	// })
	return fmt.Errorf("aws sns: configure AWS credentials and uncomment implementation")
}

// ─── Vonage ───────────────────────────────────────────────────────────────────

type VonageProvider struct {
	cfg *config.SMSConfig
}

func NewVonageProvider(cfg *config.SMSConfig) *VonageProvider {
	return &VonageProvider{cfg: cfg}
}

func (p *VonageProvider) Send(ctx context.Context, to, message string) error {
	// Production: use github.com/vonage/vonage-go-sdk
	return fmt.Errorf("vonage: add vonage-go-sdk dependency to use this provider")
}

// ─── Helper ───────────────────────────────────────────────────────────────────

func buildSMSMessage(code string, purpose models.OTPPurpose) string {
	label := strings.Title(strings.ReplaceAll(string(purpose), "_", " "))
	return fmt.Sprintf("[Auth] Your %s code is: %s. Expires in 5 minutes. Do not share.", label, code)
}
