package s3

import (
	"context"
	"io"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/s3"
)

func DownloadFile(bucket, key string, timeout time.Duration, w io.WriterAt, client S3Client) error {
	input := &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key: aws.String(key),
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	_, err := client.DownloadWithContext(ctx, w, input)
	return err
}
