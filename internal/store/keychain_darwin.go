//go:build darwin && cgo

// SPDX-FileCopyrightText: 2026 Curtis Galloway
// SPDX-License-Identifier: Apache-2.0

package store

/*
#cgo LDFLAGS: -framework Security -framework CoreFoundation
#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>
#include <stdlib.h>
#include <string.h>

static OSStatus keychain_op(int operation, const void *token, long length, int replace, void **output, long *output_len) {
    SecKeychainSetUserInteractionAllowed(false);
    SecKeychainRef keychain = NULL;
    OSStatus status = SecKeychainCopyDefault(&keychain);
    if (status != errSecSuccess) return status;
    SecKeychainStatus state = 0;
    status = SecKeychainGetStatus(keychain, &state);
    if (status != errSecSuccess) { CFRelease(keychain); return status; }
    if (!(state & kSecUnlockStateStatus)) { CFRelease(keychain); return errSecInteractionNotAllowed; }
    CFMutableDictionaryRef query = CFDictionaryCreateMutable(NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFDictionarySetValue(query,kSecClass,kSecClassGenericPassword);
    CFDictionarySetValue(query,kSecAttrService,CFSTR("op-go"));
    CFDictionarySetValue(query,kSecAttrAccount,CFSTR("service-account"));
    CFArrayRef search = CFArrayCreate(NULL,(const void **)&keychain,1,&kCFTypeArrayCallBacks);
    CFDictionarySetValue(query,kSecMatchSearchList,search);
    CFRelease(search);
    if (operation == 0) {
        // Return attributes, never data: doctor must not retrieve the token.
        CFDictionarySetValue(query,kSecReturnAttributes,kCFBooleanTrue);
        CFTypeRef attributes = NULL;
        status = SecItemCopyMatching(query,&attributes);
        if (attributes) CFRelease(attributes);
    } else if (operation == 1) {
        CFDictionarySetValue(query,kSecReturnData,kCFBooleanTrue);
        CFTypeRef data = NULL;
        status = SecItemCopyMatching(query,&data);
        if (status == errSecSuccess && data) {
            if (CFGetTypeID(data)!=CFDataGetTypeID() || CFDataGetLength((CFDataRef)data)>65536) status=errSecParam;
            else {
                *output_len=CFDataGetLength((CFDataRef)data);
                *output=malloc(*output_len ? *output_len : 1);
                if (!*output) status=errSecAllocate;
                else memcpy(*output,CFDataGetBytePtr((CFDataRef)data),*output_len);
            }
        }
        if (data) CFRelease(data);
    } else if (operation == 2) {
        CFDataRef data=CFDataCreate(NULL,token,length);
        CFMutableDictionaryRef changes=CFDictionaryCreateMutable(NULL,0,&kCFTypeDictionaryKeyCallBacks,&kCFTypeDictionaryValueCallBacks);
        CFDictionarySetValue(changes,kSecValueData,data);
        status=replace ? SecItemUpdate(query,changes) : errSecItemNotFound;
        if (status==errSecItemNotFound) {
            CFDictionaryRemoveValue(query,kSecMatchSearchList);
            CFDictionarySetValue(query,kSecUseKeychain,keychain);
            CFDictionarySetValue(query,kSecValueData,data);
            CFDictionarySetValue(query,kSecAttrLabel,CFSTR("op-go service account"));
            status=SecItemAdd(query,NULL);
        }
        CFRelease(changes); CFRelease(data);
    } else if (operation == 3) status=SecItemDelete(query);
    else status=errSecParam;
    CFRelease(query); CFRelease(keychain);
    return status;
}
*/
import "C"

import (
	"context"
	"unsafe"
)

func nativeOperation(ctx context.Context, req request) (result response, resultErr error) {
	defer func() {
		if err := ctx.Err(); err != nil {
			result = response{}
			resultErr = err
		}
	}()
	if err := ctx.Err(); err != nil {
		return response{}, err
	}
	if req.Backend != "keychain" {
		return response{}, ErrUnavailable
	}
	operation := map[string]int{"status": 0, "read": 1, "write": 2, "delete": 3}
	op, ok := operation[req.Operation]
	if !ok {
		return response{}, ErrDenied
	}
	var token unsafe.Pointer
	if op == 2 {
		normalized, err := NormalizeToken(req.Token)
		if err != nil {
			return response{}, err
		}
		req.Token = normalized
		token = C.CBytes([]byte(req.Token))
		defer C.free(token)
	}
	var output unsafe.Pointer
	var size C.long
	replace := C.int(0)
	if req.Replace {
		replace = 1
	}
	status := C.keychain_op(C.int(op), token, C.long(len(req.Token)), replace, &output, &size)
	if output != nil {
		defer C.free(output)
	}
	switch status {
	case C.errSecSuccess:
		if op == 1 {
			value, err := NormalizeToken(string(C.GoBytes(output, C.int(size))))
			return response{Token: value}, err
		}
		return response{Present: true}, nil
	case C.errSecItemNotFound:
		if op == 0 {
			return response{}, nil
		}
		return response{}, ErrNotFound
	case C.errSecDuplicateItem:
		return response{}, ErrExists
	case C.errSecInteractionNotAllowed:
		return response{}, ErrLocked
	case C.errSecAuthFailed, C.errSecUserCanceled:
		return response{}, ErrDenied
	default:
		return response{}, ErrUnavailable
	}
}
