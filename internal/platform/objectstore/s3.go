// Package objectstore stores files in any S3 compatible service: AWS S3,
// Garage, Cloudflare R2, Backblaze B2, MinIO, SeaweedFS, DigitalOcean Spaces.
package objectstore

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/fatihacan1/warden/internal/config"
)

// Store is the subset of object storage Warden needs.
type Store interface {
	Put(ctx context.Context, key, contentType string, body []byte) error
	Delete(ctx context.Context, key string) error
	URL(ctx context.Context, key string) (string, error)
	Ping(ctx context.Context) error
}

// ErrDisabled is returned when S3 is not configured.
var ErrDisabled = errors.New("objectstore: disabled")

// S3 implements Store.
type S3 struct {
	client     *s3.Client
	presign    *s3.PresignClient
	bucket     string
	publicBase string
	presignTTL time.Duration
}

// NewS3 creates a client. Checksums are only sent when required: several S3
// compatible servers reject the newer default CRC trailers.
func NewS3(ctx context.Context, cfg config.S3Config) (*S3, error) {
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx,
		awsconfig.WithRegion(cfg.Region),
		awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(cfg.AccessKeyID, cfg.SecretAccessKey, "")),
	)
	if err != nil {
		return nil, fmt.Errorf("s3: config: %w", err)
	}
	client := s3.NewFromConfig(awsCfg, func(o *s3.Options) {
		if cfg.Endpoint != "" {
			o.BaseEndpoint = aws.String(cfg.Endpoint)
		}
		o.UsePathStyle = cfg.UsePathStyle
		o.RequestChecksumCalculation = aws.RequestChecksumCalculationWhenRequired
		o.ResponseChecksumValidation = aws.ResponseChecksumValidationWhenRequired
	})
	return &S3{
		client:     client,
		presign:    s3.NewPresignClient(client),
		bucket:     cfg.Bucket,
		publicBase: strings.TrimRight(cfg.PublicBaseURL, "/"),
		presignTTL: cfg.PresignTTL,
	}, nil
}

func (s *S3) Put(ctx context.Context, key, contentType string, body []byte) error {
	_, err := s.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:        aws.String(s.bucket),
		Key:           aws.String(key),
		Body:          bytes.NewReader(body),
		ContentLength: aws.Int64(int64(len(body))),
		ContentType:   aws.String(contentType),
		CacheControl:  aws.String("public, max-age=31536000, immutable"),
	})
	return err
}

func (s *S3) Delete(ctx context.Context, key string) error {
	_, err := s.client.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: aws.String(s.bucket), Key: aws.String(key)})
	return err
}

// URL returns a public URL when S3_PUBLIC_BASE_URL is set, otherwise a
// presigned GET URL.
func (s *S3) URL(ctx context.Context, key string) (string, error) {
	if s.publicBase != "" {
		return s.publicBase + "/" + key, nil
	}
	req, err := s.presign.PresignGetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(s.bucket), Key: aws.String(key)},
		s3.WithPresignExpires(s.presignTTL))
	if err != nil {
		return "", err
	}
	return req.URL, nil
}

func (s *S3) Ping(ctx context.Context) error {
	_, err := s.client.HeadBucket(ctx, &s3.HeadBucketInput{Bucket: aws.String(s.bucket)})
	return err
}

// Disabled is a Store that rejects every operation.
type Disabled struct{}

func (Disabled) Put(context.Context, string, string, []byte) error { return ErrDisabled }
func (Disabled) Delete(context.Context, string) error              { return nil }
func (Disabled) URL(context.Context, string) (string, error)       { return "", ErrDisabled }
func (Disabled) Ping(context.Context) error                        { return nil }
