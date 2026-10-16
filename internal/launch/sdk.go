// SPDX-FileCopyrightText: 2026 Curtis Galloway
// SPDX-License-Identifier: Apache-2.0

package launch

import (
	"context"
	"errors"
	onepassword "github.com/1password/onepassword-sdk-go"
	"runtime"
)

func newSDKResolver(ctx context.Context, token string) (resolver, error) {
	client, err := onepassword.NewClient(ctx, onepassword.WithServiceAccountToken(token), onepassword.WithIntegrationInfo("op-go", "0.1.0-dev"))
	if err != nil {
		return nil, err
	}
	// Keep the whole client alive: its finalizer releases the native SDK handle.
	return &sdkResolver{client}, nil
}

type sdkResolver struct{ client *onepassword.Client }

func (r *sdkResolver) Resolve(ctx context.Context, ref string) (string, error) {
	value, err := r.client.Secrets().Resolve(ctx, ref)
	runtime.KeepAlive(r.client)
	return value, err
}
func classifySDKError(err error, code int, message string) error {
	var rate *onepassword.RateLimitExceededError
	if errors.As(err, &rate) {
		return &Error{23, "1Password rate limit reached; retry later"}
	}
	return &Error{code, message}
}
