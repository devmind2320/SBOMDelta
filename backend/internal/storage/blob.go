package storage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"

	"sbomdelta/internal/config"
)

// BlobStore archives raw SBOM documents. Postgres holds the queryable
// projection; the full CycloneDX document lives here, where a multi-megabyte
// JSON blob is cheap and never scanned by a query planner.
type BlobStore struct {
	client *minio.Client
	bucket string
}

// NewBlobStore connects to the object store and creates the bucket if it does
// not exist, which is what makes a fresh MinIO container work out of the box.
func NewBlobStore(ctx context.Context, cfg config.Blob) (*BlobStore, error) {
	client, err := minio.New(cfg.Endpoint, &minio.Options{
		Creds:        credentials.NewStaticV4(cfg.AccessKey, cfg.SecretKey, ""),
		Secure:       cfg.UseSSL,
		Region:       cfg.Region,
		BucketLookup: bucketLookup(cfg.PathStyle),
	})
	if err != nil {
		return nil, fmt.Errorf("connect to blob store: %w", err)
	}

	exists, err := client.BucketExists(ctx, cfg.Bucket)
	if err != nil {
		return nil, fmt.Errorf("check bucket %q: %w", cfg.Bucket, err)
	}
	if !exists {
		if err := client.MakeBucket(ctx, cfg.Bucket, minio.MakeBucketOptions{Region: cfg.Region}); err != nil {
			return nil, fmt.Errorf("create bucket %q: %w", cfg.Bucket, err)
		}
	}
	return &BlobStore{client: client, bucket: cfg.Bucket}, nil
}

func bucketLookup(pathStyle bool) minio.BucketLookupType {
	if pathStyle {
		return minio.BucketLookupPath
	}
	return minio.BucketLookupDNS
}

// SBOMKey is the object key for one scan's SBOM. Keying by repository and
// commit rather than by scan ID means the same commit scanned twice reuses one
// object, and the layout stays browsable.
func SBOMKey(repositoryID int64, commitSHA string) string {
	return path.Join("sboms", fmt.Sprintf("repo-%d", repositoryID), commitSHA, "cyclonedx.json")
}

// PutSBOM uploads a document and returns its s3:// location and content hash.
// The hash lets a later read confirm it got the bytes the scan recorded.
func (b *BlobStore) PutSBOM(ctx context.Context, key string, document []byte) (location, digest string, err error) {
	sum := sha256.Sum256(document)
	digest = hex.EncodeToString(sum[:])

	_, err = b.client.PutObject(ctx, b.bucket, key, bytes.NewReader(document), int64(len(document)),
		minio.PutObjectOptions{
			ContentType: "application/vnd.cyclonedx+json",
			UserMetadata: map[string]string{
				"sha256": digest,
			},
		})
	if err != nil {
		return "", "", fmt.Errorf("upload sbom %q: %w", key, err)
	}
	return "s3://" + b.bucket + "/" + key, digest, nil
}

// GetSBOM downloads a document previously stored with PutSBOM. It accepts
// either a bare key or the s3:// location recorded on the scan.
func (b *BlobStore) GetSBOM(ctx context.Context, locationOrKey string) ([]byte, error) {
	key, err := b.objectKey(locationOrKey)
	if err != nil {
		return nil, err
	}

	object, err := b.client.GetObject(ctx, b.bucket, key, minio.GetObjectOptions{})
	if err != nil {
		return nil, fmt.Errorf("open sbom %q: %w", key, err)
	}
	defer object.Close()

	document, err := io.ReadAll(object)
	if err != nil {
		return nil, fmt.Errorf("read sbom %q: %w", key, err)
	}
	return document, nil
}

// PresignSBOM issues a time-limited download URL, so the dashboard can offer
// the raw SBOM without proxying megabytes through the API.
func (b *BlobStore) PresignSBOM(ctx context.Context, locationOrKey string, ttl time.Duration) (string, error) {
	key, err := b.objectKey(locationOrKey)
	if err != nil {
		return "", err
	}
	signed, err := b.client.PresignedGetObject(ctx, b.bucket, key, ttl, url.Values{})
	if err != nil {
		return "", fmt.Errorf("presign sbom %q: %w", key, err)
	}
	return signed.String(), nil
}

// objectKey normalizes an s3://bucket/key location back to a bare key, and
// rejects locations pointing at a different bucket than this store owns.
func (b *BlobStore) objectKey(locationOrKey string) (string, error) {
	if !strings.HasPrefix(locationOrKey, "s3://") {
		return locationOrKey, nil
	}
	parsed, err := url.Parse(locationOrKey)
	if err != nil {
		return "", fmt.Errorf("parse blob location %q: %w", locationOrKey, err)
	}
	if parsed.Host != b.bucket {
		return "", fmt.Errorf("blob location %q is in bucket %q, not %q", locationOrKey, parsed.Host, b.bucket)
	}
	key := strings.TrimPrefix(parsed.Path, "/")
	if key == "" {
		return "", fmt.Errorf("blob location %q has no object key", locationOrKey)
	}
	return key, nil
}
