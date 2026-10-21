// SPDX-FileCopyrightText: 2026 Curtis Galloway
// SPDX-License-Identifier: Apache-2.0

package launch

import (
	"context"
	"errors"
	onepassword "github.com/1password/onepassword-sdk-go"
	"runtime"
)

// IntegrationVersion is reported to 1Password; the CLI sets it to its build version.
var IntegrationVersion = "dev"

func newSDKResolver(ctx context.Context, token string) (resolver, error) {
	client, err := onepassword.NewClient(ctx, onepassword.WithServiceAccountToken(token), onepassword.WithIntegrationInfo("op-go", IntegrationVersion))
	if err != nil {
		return nil, err
	}
	// Keep the whole client alive: its finalizer releases the native SDK handle.
	return &sdkResolver{client}, nil
}

type sdkResolver struct{ client *onepassword.Client }

func (r *sdkResolver) Resolve(ctx context.Context, ref string) (string, error) {
	value, err := resolveSDKReference(ctx, ref, r.client.Secrets().ResolveAll)
	runtime.KeepAlive(r.client)
	return value, err
}

// ResolveAll preserves per-reference error categories that Resolve reduces to text.
// Resolve one reference per call to preserve sequential, fail-fast behavior.
func resolveSDKReference(ctx context.Context, ref string, resolveAll func(context.Context, []string) (onepassword.ResolveAllResponse, error)) (string, error) {
	response, err := resolveAll(ctx, []string{ref})
	if err != nil {
		return "", err
	}
	result, ok := response.IndividualResponses[ref]
	if !ok || len(response.IndividualResponses) != 1 || (result.Content == nil) == (result.Error == nil) {
		return "", &sdkReferenceError{} // Missing or contradictory response; never export a partial value.
	}
	if result.Error != nil {
		return "", &sdkReferenceError{kind: result.Error.Type}
	}
	return result.Content.Secret, nil
}

type sdkReferenceError struct {
	kind onepassword.ResolveReferenceErrorTypes
}

func (*sdkReferenceError) Error() string { return "secret reference resolution failed" }

func classifySDKError(err error, code int, message string) error {
	var reference *sdkReferenceError
	if errors.As(err, &reference) {
		switch reference.kind {
		case onepassword.ResolveReferenceErrorTypeVariantParsing:
			return &Error{2, "secret reference syntax is invalid; use IDs for names containing unsupported characters"}
		case onepassword.ResolveReferenceErrorTypeVariantVaultNotFound:
			return &Error{3, "secret reference vault not found or unavailable"}
		case onepassword.ResolveReferenceErrorTypeVariantItemNotFound:
			return &Error{3, "secret reference item not found or unavailable"}
		case onepassword.ResolveReferenceErrorTypeVariantFieldNotFound:
			return &Error{3, "secret reference field not found"}
		case onepassword.ResolveReferenceErrorTypeVariantNoMatchingSections:
			return &Error{3, "secret reference section not found"}
		case onepassword.ResolveReferenceErrorTypeVariantTooManyVaults:
			return &Error{3, "secret reference vault name is ambiguous; use its ID"}
		case onepassword.ResolveReferenceErrorTypeVariantTooManyItems:
			return &Error{3, "secret reference item name is ambiguous; use its ID"}
		case onepassword.ResolveReferenceErrorTypeVariantTooManyMatchingFields:
			return &Error{3, "secret reference field is ambiguous; use its section and ID"}
		case onepassword.ResolveReferenceErrorTypeVariantIncompatibleTOTPQueryParameterField,
			onepassword.ResolveReferenceErrorTypeVariantIncompatibleSSHKeyQueryParameterField,
			onepassword.ResolveReferenceErrorTypeVariantUnsupportedFileFormat:
			return &Error{3, "secret reference format is incompatible with the field"}
		default:
			return &Error{20, "secret resolution failed; SDK did not provide a supported error category"}
		}
	}
	var expired *onepassword.DesktopSessionExpiredError
	if errors.As(err, &expired) {
		return &Error{10, "1Password session expired"}
	}

	var rate *onepassword.RateLimitExceededError
	if errors.As(err, &rate) {
		return &Error{23, "1Password rate limit reached; retry later"}
	}
	return &Error{code, message}
}
