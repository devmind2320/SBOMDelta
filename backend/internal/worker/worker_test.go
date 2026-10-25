package worker

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"sbomdelta/internal/queue"
)

// A malformed initial_scan job, or one landing on a worker without GitHub,
// fails loudly rather than being marked done with nothing scanned.
func TestHandleRejectsUnrunnableInitialScanJobs(t *testing.T) {
	w := &Worker{}
	tests := []struct {
		name    string
		payload string
		want    string
	}{
		{"no repository id", `{}`, "no repository id"},
		{"undecodable payload", `{"repositoryId":"x"}`, "decode initial scan payload"},
		{"github disabled", `{"repositoryId":7}`, "GitHub integration is disabled"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := w.handle(context.Background(), &queue.Job{Kind: queue.KindInitialScan, Payload: json.RawMessage(tt.payload)})
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("handle() error = %v, want it to mention %q", err, tt.want)
			}
		})
	}
}
