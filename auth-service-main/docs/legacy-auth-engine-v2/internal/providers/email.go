//go:build legacy
// +build legacy

package providers

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/smtp"
	"strings"

	"github.com/enterprise/auth-engine/internal/config"
	"github.com/enterprise/auth-engine/internal/models"
	"github.com/sendgrid/sendgrid-go"
	"github.com/sendgrid/sendgrid-go/helpers/mail"
)

// ─── Interface ────────────────────────────────────────────────────────────────

type EmailProvider interface {
	Send(ctx context.Context, to, subject, htmlBody, textBody string) error
}

// ─── Factory ──────────────────────────────────────────────────────────────────

func NewEmailProvider(cfg *config.EmailConfig) (EmailProvider, error) {
	switch cfg.Provider {
	case "sendgrid":
		return NewSendGridProvider(cfg), nil
	case "ses":
		return NewSESProvider(cfg), nil
	case "smtp":
		return NewSMTPProvider(cfg), nil
	case "mailgun":
		return NewMailgunProvider(cfg), nil
	default:
		return nil, fmt.Errorf("unknown email provider: %s", cfg.Provider)
	}
}

// ─── Notifier Adapter ────────────────────────────────────────────────────────

type EmailNotifier struct {
	provider EmailProvider
	from     string
	fromName string
}

func NewEmailNotifier(provider EmailProvider, cfg *config.EmailConfig) *EmailNotifier {
	return &EmailNotifier{provider: provider, from: cfg.From, fromName: cfg.FromName}
}

func (n *EmailNotifier) SendEmailOTP(ctx context.Context, to, code string, purpose models.OTPPurpose) error {
	subject, html := buildOTPEmail(code, purpose)
	return n.provider.Send(ctx, to, subject, html, stripHTML(html))
}

// ─── SendGrid ─────────────────────────────────────────────────────────────────

type SendGridProvider struct {
	client   *sendgrid.Client
	from     string
	fromName string
}

func NewSendGridProvider(cfg *config.EmailConfig) *SendGridProvider {
	return &SendGridProvider{
		client:   sendgrid.NewSendClient(cfg.SendGridAPIKey),
		from:     cfg.From,
		fromName: cfg.FromName,
	}
}

func (p *SendGridProvider) Send(ctx context.Context, to, subject, htmlBody, textBody string) error {
	from := mail.NewEmail(p.fromName, p.from)
	recipient := mail.NewEmail("", to)
	message := mail.NewSingleEmail(from, subject, recipient, textBody, htmlBody)
	resp, err := p.client.SendWithContext(ctx, message)
	if err != nil {
		return fmt.Errorf("sendgrid: %w", err)
	}
	if resp.StatusCode >= 400 {
		return fmt.Errorf("sendgrid: status %d: %s", resp.StatusCode, resp.Body)
	}
	return nil
}

// ─── AWS SES ──────────────────────────────────────────────────────────────────

type SESProvider struct {
	cfg *config.EmailConfig
}

func NewSESProvider(cfg *config.EmailConfig) *SESProvider {
	return &SESProvider{cfg: cfg}
}

func (p *SESProvider) Send(ctx context.Context, to, subject, htmlBody, textBody string) error {
	// AWS SDK v2 SES integration
	// In production: use github.com/aws/aws-sdk-go-v2/service/sesv2
	// Keeping as interface stub for modularity
	return fmt.Errorf("aws ses: configure AWS credentials and uncomment implementation")
}

// ─── SMTP ─────────────────────────────────────────────────────────────────────

type SMTPProvider struct {
	cfg *config.EmailConfig
}

func NewSMTPProvider(cfg *config.EmailConfig) *SMTPProvider {
	return &SMTPProvider{cfg: cfg}
}

func (p *SMTPProvider) Send(ctx context.Context, to, subject, htmlBody, textBody string) error {
	auth := smtp.PlainAuth("", p.cfg.SMTPUsername, p.cfg.SMTPPassword, p.cfg.SMTPHost)
	addr := fmt.Sprintf("%s:%d", p.cfg.SMTPHost, p.cfg.SMTPPort)

	msg := buildMIMEMessage(p.cfg.From, p.cfg.FromName, to, subject, htmlBody, textBody)

	tlsConfig := &tls.Config{
		InsecureSkipVerify: false,
		ServerName:         p.cfg.SMTPHost,
	}
	conn, err := tls.Dial("tcp", addr, tlsConfig)
	if err != nil {
		return fmt.Errorf("smtp tls dial: %w", err)
	}
	c, err := smtp.NewClient(conn, p.cfg.SMTPHost)
	if err != nil {
		return fmt.Errorf("smtp client: %w", err)
	}
	defer c.Quit()

	if err = c.Auth(auth); err != nil {
		return fmt.Errorf("smtp auth: %w", err)
	}
	if err = c.Mail(p.cfg.From); err != nil {
		return fmt.Errorf("smtp mail: %w", err)
	}
	if err = c.Rcpt(to); err != nil {
		return fmt.Errorf("smtp rcpt: %w", err)
	}
	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("smtp data: %w", err)
	}
	defer w.Close()
	_, err = w.Write([]byte(msg))
	return err
}

// ─── Mailgun ──────────────────────────────────────────────────────────────────

type MailgunProvider struct {
	cfg *config.EmailConfig
}

func NewMailgunProvider(cfg *config.EmailConfig) *MailgunProvider {
	return &MailgunProvider{cfg: cfg}
}

func (p *MailgunProvider) Send(ctx context.Context, to, subject, htmlBody, textBody string) error {
	// Production: use github.com/mailgun/mailgun-go/v4
	return fmt.Errorf("mailgun: add mailgun-go dependency to use this provider")
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func buildOTPEmail(code string, purpose models.OTPPurpose) (subject, html string) {
	purposeLabel := map[models.OTPPurpose]string{
		models.OTPPurposeLogin:         "Sign In",
		models.OTPPurposeRegister:      "Registration",
		models.OTPPurposeVerifyEmail:   "Email Verification",
		models.OTPPurposeVerifyPhone:   "Phone Verification",
		models.OTPPurposePasswordReset: "Password Reset",
		models.OTPPurposeMFA:           "Two-Factor Authentication",
		models.OTPPurposeTransaction:   "Transaction Authorization",
	}
	label := purposeLabel[purpose]
	if label == "" {
		label = "Verification"
	}

	subject = fmt.Sprintf("Your %s Code: %s", label, code)
	html = fmt.Sprintf(`<!DOCTYPE html>
<html>
<body style="font-family:sans-serif;max-width:600px;margin:0 auto;padding:20px">
  <h2>%s Code</h2>
  <p>Your verification code is:</p>
  <div style="font-size:36px;font-weight:bold;letter-spacing:8px;color:#2563eb;padding:20px;background:#f3f4f6;border-radius:8px;text-align:center">%s</div>
  <p style="color:#6b7280;font-size:14px">This code expires in 5 minutes. Do not share it with anyone.</p>
</body>
</html>`, label, code)
	return subject, html
}

func buildMIMEMessage(from, fromName, to, subject, html, text string) string {
	return fmt.Sprintf("From: %s <%s>\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n%s",
		fromName, from, to, subject, html)
}

func stripHTML(h string) string {
	return strings.ReplaceAll(strings.ReplaceAll(h, "<br>", "\n"), "\r\n", "\n")
}
