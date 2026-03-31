package auth

import (
	"net/http"
	"reflect"
	"testing"
)

func TestGetApiKey(t *testing.T) {
	tests := []struct {
		name       string
		headers    http.Header
		wantKey    string
		wantErr    bool
		errCompare error
	}{
		{
			name:    "Valid api key",
			headers: http.Header{"Authorization": []string{"ApiKey my-secret-key"}},
			wantKey: "my-secret-key",
			wantErr: false,
		},
		{
			name:       "missing header",
			headers:    http.Header{},
			wantKey:    "",
			wantErr:    true,
			errCompare: ErrNoAuthHeaderIncluded,
		},
		{
			name: "wrong prefix",
			headers: http.Header{
				"Authorization": []string{"Bearer token123"},
			},
			wantKey: "",
			wantErr: true,
		},
		{
			name: "malformed header - no key",
			headers: http.Header{
				"Authorization": []string{"ApiKey"},
			},
			wantKey: "",
			wantErr: true,
		},
		{
			name: "empty Authorization value",
			headers: http.Header{
				"Authorization": []string{""},
			},
			wantKey:    "",
			wantErr:    true,
			errCompare: ErrNoAuthHeaderIncluded,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotKey, err := GetAPIKey(tt.headers)

			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nill")
				}

				if tt.errCompare != nil && !reflect.DeepEqual(err, tt.errCompare) {
					t.Fatalf("expected error %v, got %v", tt.errCompare, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected errror: %v", err)
			}

			if gotKey != tt.wantKey {
				t.Fatalf("expected key %q, got %q", tt.wantKey, gotKey)
			}
		})
	}
}
