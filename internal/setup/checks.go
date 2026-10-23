package setup

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	amqp "github.com/rabbitmq/amqp091-go"
	"github.com/redis/go-redis/v9"

	"github.com/fatihacan1/warden/internal/config"
	"github.com/fatihacan1/warden/internal/mailer"
	"github.com/fatihacan1/warden/internal/platform/objectstore"
)

// check tests one connection with the submitted values and returns a short,
// human readable result. Errors never echo passwords back.
func check(ctx context.Context, kind string, v map[string]string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	switch kind {
	case "postgres":
		conn, err := pgx.Connect(ctx, v["DATABASE_URL"])
		if err != nil {
			return "", clean(err, v["DATABASE_URL"])
		}
		defer conn.Close(context.Background())
		var version string
		if err := conn.QueryRow(ctx, "SHOW server_version").Scan(&version); err != nil {
			return "", clean(err, v["DATABASE_URL"])
		}
		var create bool
		_ = conn.QueryRow(ctx, "SELECT has_database_privilege(current_database(), 'CREATE')").Scan(&create)
		msg := "Connected to PostgreSQL " + version + "."
		if !create {
			msg += " Warning: this user cannot create tables, so migrations will fail."
		}
		return msg, nil

	case "redis":
		opt, err := redis.ParseURL(v["REDIS_URL"])
		if err != nil {
			return "", errors.New("invalid Redis URL")
		}
		c := redis.NewClient(opt)
		defer c.Close()
		info, err := c.Info(ctx, "server").Result()
		if err != nil {
			return "", clean(err, v["REDIS_URL"])
		}
		version := "?"
		for _, line := range strings.Split(info, "\n") {
			if after, ok := strings.CutPrefix(strings.TrimSpace(line), "redis_version:"); ok {
				version = after
			}
		}
		return "Connected to Redis " + version + ".", nil

	case "rabbitmq":
		if v["RABBITMQ_URL"] == "" {
			return "RabbitMQ is off: events are not published (webhooks still work).", nil
		}
		conn, err := amqp.DialConfig(v["RABBITMQ_URL"], amqp.Config{Dial: amqp.DefaultDial(5 * time.Second)})
		if err != nil {
			return "", clean(err, v["RABBITMQ_URL"])
		}
		defer conn.Close()
		return "Connected to RabbitMQ.", nil

	case "s3":
		if v["S3_ENABLED"] != "true" {
			return "Profile photos are off.", nil
		}
		cfg := config.S3Config{Enabled: true, Endpoint: v["S3_ENDPOINT"], Region: v["S3_REGION"], Bucket: v["S3_BUCKET"],
			AccessKeyID: v["S3_ACCESS_KEY_ID"], SecretAccessKey: v["S3_SECRET_ACCESS_KEY"], UsePathStyle: v["S3_USE_PATH_STYLE"] == "true",
			PresignTTL: time.Hour}
		s3, err := objectstore.NewS3(ctx, cfg)
		if err != nil {
			return "", err
		}
		if err := s3.Ping(ctx); err != nil {
			return "", fmt.Errorf("bucket %q is not reachable with these credentials: %w", cfg.Bucket, err)
		}
		return "Bucket " + cfg.Bucket + " is reachable.", nil

	case "smtp":
		switch v["MAIL_DELIVERY"] {
		case "inbox":
			return "Nothing to test: emails are kept in the admin Inbox.", nil
		case "direct":
			return "Nothing to test here. After starting Warden run `warden mail-test you@example.com` to check direct delivery.", nil
		}
		if v["SMTP_HOST"] == "" {
			return "", errors.New("enter the SMTP host, or pick another delivery mode")
		}
		port, err := strconv.Atoi(v["SMTP_PORT"])
		if err != nil {
			return "", errors.New("port must be a number")
		}
		client, err := mailer.NewClient(config.SMTPConfig{Host: v["SMTP_HOST"], Port: port, Username: v["SMTP_USERNAME"],
			Password: v["SMTP_PASSWORD"], TLSPolicy: v["SMTP_TLS_POLICY"]})
		if err != nil {
			return "", err
		}
		if err := client.DialWithContext(ctx); err != nil {
			return "", clean(err, v["SMTP_PASSWORD"])
		}
		_ = client.Close()
		if v["SMTP_USERNAME"] != "" {
			return "Connected to " + v["SMTP_HOST"] + " and signed in.", nil
		}
		return "Connected to " + v["SMTP_HOST"] + ".", nil
	}
	return "", fmt.Errorf("unknown check %q", kind)
}

// clean removes a secret (URL with password, SMTP password) from an error.
func clean(err error, secret string) error {
	msg := err.Error()
	if secret != "" {
		msg = strings.ReplaceAll(msg, secret, "***")
	}
	return errors.New(msg)
}
