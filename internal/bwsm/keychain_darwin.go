//go:build darwin && cgo

package bwsm

/*
#cgo darwin LDFLAGS: -framework CoreFoundation -framework Security
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <stdlib.h>

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"

static CFMutableDictionaryRef agentSecretBWSMKeychainQuery(CFStringRef service, CFStringRef account) {
	CFMutableDictionaryRef query = CFDictionaryCreateMutable(
		NULL,
		0,
		&kCFTypeDictionaryKeyCallBacks,
		&kCFTypeDictionaryValueCallBacks
	);
	CFDictionarySetValue(query, kSecClass, kSecClassGenericPassword);
	CFDictionarySetValue(query, kSecAttrService, service);
	CFDictionarySetValue(query, kSecAttrAccount, account);
	CFDictionarySetValue(query, kSecUseAuthenticationUI, kSecUseAuthenticationUIFail);
	return query;
}

static CFMutableArrayRef agentSecretBWSMTrustedApplicationArray(void) {
	return CFArrayCreateMutable(NULL, 0, &kCFTypeArrayCallBacks);
}

static OSStatus agentSecretBWSMAppendTrustedApplication(CFMutableArrayRef applications, const char *path) {
	SecTrustedApplicationRef application = NULL;
	OSStatus status = SecTrustedApplicationCreateFromPath(path, &application);
	if (status != errSecSuccess) {
		return status;
	}
	CFArrayAppendValue(applications, application);
	CFRelease(application);
	return errSecSuccess;
}

static OSStatus agentSecretBWSMCreateAccess(CFArrayRef applications, SecAccessRef *access) {
	return SecAccessCreate(CFSTR("Agent Secret Bitwarden Secrets Manager tokens"), applications, access);
}

static CFMutableDictionaryRef agentSecretBWSMKeychainAddQuery(CFStringRef service, CFStringRef account, CFDataRef data, SecAccessRef access) {
	CFMutableDictionaryRef query = agentSecretBWSMKeychainQuery(service, account);
	CFDictionarySetValue(query, kSecValueData, data);
	CFDictionarySetValue(query, kSecAttrAccessible, kSecAttrAccessibleWhenUnlockedThisDeviceOnly);
	if (access != NULL) {
		CFDictionarySetValue(query, kSecAttrAccess, access);
	}
	CFDictionarySetValue(query, kSecUseAuthenticationUI, kSecUseAuthenticationUIFail);
	return query;
}

static CFMutableDictionaryRef agentSecretBWSMKeychainDataQuery(CFStringRef service, CFStringRef account) {
	CFMutableDictionaryRef query = agentSecretBWSMKeychainQuery(service, account);
	CFDictionarySetValue(query, kSecReturnData, kCFBooleanTrue);
	CFDictionarySetValue(query, kSecMatchLimit, kSecMatchLimitOne);
	return query;
}

static void agentSecretBWSMRestoreUserInteraction(Boolean restored, Boolean previous) {
	if (restored) {
		SecKeychainSetUserInteractionAllowed(previous);
	}
}

static OSStatus agentSecretBWSMDisableUserInteraction(Boolean *previous, Boolean *restored) {
	*previous = true;
	*restored = false;
	OSStatus status = SecKeychainGetUserInteractionAllowed(previous);
	if (status != errSecSuccess) {
		return status;
	}
	status = SecKeychainSetUserInteractionAllowed(false);
	if (status == errSecSuccess) {
		*restored = true;
	}
	return status;
}

static OSStatus agentSecretBWSMSecItemCopyMatchingNoUI(CFDictionaryRef query, CFTypeRef *result) {
	Boolean previous;
	Boolean restored;
	OSStatus status = agentSecretBWSMDisableUserInteraction(&previous, &restored);
	if (status == errSecSuccess) {
		status = SecItemCopyMatching(query, result);
	}
	agentSecretBWSMRestoreUserInteraction(restored, previous);
	return status;
}

static OSStatus agentSecretBWSMSecItemAddNoUI(CFDictionaryRef query) {
	Boolean previous;
	Boolean restored;
	OSStatus status = agentSecretBWSMDisableUserInteraction(&previous, &restored);
	if (status == errSecSuccess) {
		status = SecItemAdd(query, NULL);
	}
	agentSecretBWSMRestoreUserInteraction(restored, previous);
	return status;
}

static OSStatus agentSecretBWSMSecItemDeleteNoUI(CFDictionaryRef query) {
	Boolean previous;
	Boolean restored;
	OSStatus status = agentSecretBWSMDisableUserInteraction(&previous, &restored);
	if (status == errSecSuccess) {
		status = SecItemDelete(query);
	}
	agentSecretBWSMRestoreUserInteraction(restored, previous);
	return status;
}

#pragma clang diagnostic pop
*/
import "C"

import (
	"context"
	"fmt"
	"sync"
	"unsafe"
)

// keychainInteractionMu serializes SecKeychainSetUserInteractionAllowed because
// the Keychain interaction setting is process-wide.
//
//nolint:gochecknoglobals
var keychainInteractionMu sync.Mutex

func keychainGet(ctx context.Context, service string, account string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	serviceRef := cfString(service)
	defer C.CFRelease(C.CFTypeRef(serviceRef))
	accountRef := cfString(account)
	defer C.CFRelease(C.CFTypeRef(accountRef))
	query := C.agentSecretBWSMKeychainDataQuery(serviceRef, accountRef)
	defer C.CFRelease(C.CFTypeRef(query))

	var result C.CFTypeRef
	keychainInteractionMu.Lock()
	defer keychainInteractionMu.Unlock()
	status := C.agentSecretBWSMSecItemCopyMatchingNoUI(C.CFDictionaryRef(query), &result) //nolint:gocritic // cgo macro expansion confuses dupSubExpr.
	if status == C.errSecItemNotFound {
		return nil, ErrTokenNotFound
	}
	if status != C.errSecSuccess {
		return nil, keychainStatusError("read", status)
	}
	defer C.CFRelease(result)
	dataRef := C.CFDataRef(result)
	length := C.CFDataGetLength(dataRef)
	if length == 0 {
		return []byte{}, nil
	}
	ptr := C.CFDataGetBytePtr(dataRef)
	return C.GoBytes(unsafe.Pointer(ptr), C.int(length)), nil
}

func keychainPut(ctx context.Context, service string, account string, data []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	serviceRef := cfString(service)
	defer C.CFRelease(C.CFTypeRef(serviceRef))
	accountRef := cfString(account)
	defer C.CFRelease(C.CFTypeRef(accountRef))
	dataRef := cfData(data)
	defer C.CFRelease(C.CFTypeRef(dataRef))

	query := C.agentSecretBWSMKeychainQuery(serviceRef, accountRef)
	defer C.CFRelease(C.CFTypeRef(query))

	access, err := keychainAccess(trustedKeychainApplicationPaths())
	if err != nil {
		return err
	}
	if access != keychainNilAccess() {
		defer C.CFRelease(C.CFTypeRef(access))
	}
	addQuery := C.agentSecretBWSMKeychainAddQuery(serviceRef, accountRef, dataRef, access)
	defer C.CFRelease(C.CFTypeRef(addQuery))
	keychainInteractionMu.Lock()
	defer keychainInteractionMu.Unlock()
	status := C.agentSecretBWSMSecItemAddNoUI(C.CFDictionaryRef(addQuery))
	if status == C.errSecDuplicateItem {
		status = C.agentSecretBWSMSecItemDeleteNoUI(C.CFDictionaryRef(query))
		if status == C.errSecSuccess || status == C.errSecItemNotFound {
			status = C.agentSecretBWSMSecItemAddNoUI(C.CFDictionaryRef(addQuery))
		}
	}
	if status != C.errSecSuccess {
		return keychainStatusError("write", status)
	}
	return nil
}

func keychainDelete(ctx context.Context, service string, account string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	serviceRef := cfString(service)
	defer C.CFRelease(C.CFTypeRef(serviceRef))
	accountRef := cfString(account)
	defer C.CFRelease(C.CFTypeRef(accountRef))
	query := C.agentSecretBWSMKeychainQuery(serviceRef, accountRef)
	defer C.CFRelease(C.CFTypeRef(query))

	keychainInteractionMu.Lock()
	defer keychainInteractionMu.Unlock()
	status := C.agentSecretBWSMSecItemDeleteNoUI(C.CFDictionaryRef(query))
	if status == C.errSecItemNotFound {
		return false, nil
	}
	if status != C.errSecSuccess {
		return false, keychainStatusError("delete", status)
	}
	return true, nil
}

func cfString(value string) C.CFStringRef {
	cValue := C.CString(value)
	defer C.free(unsafe.Pointer(cValue))
	return C.CFStringCreateWithCString(C.CFAllocatorRef(unsafe.Pointer(nil)), cValue, C.kCFStringEncodingUTF8)
}

func cfData(data []byte) C.CFDataRef {
	if len(data) == 0 {
		return C.CFDataCreate(C.CFAllocatorRef(unsafe.Pointer(nil)), nil, 0)
	}
	return C.CFDataCreate(C.CFAllocatorRef(unsafe.Pointer(nil)), (*C.UInt8)(unsafe.Pointer(&data[0])), C.CFIndex(len(data)))
}

func keychainAccess(paths []string) (C.SecAccessRef, error) {
	if len(paths) == 0 {
		return keychainNilAccess(), nil
	}
	applications := C.agentSecretBWSMTrustedApplicationArray()
	defer C.CFRelease(C.CFTypeRef(applications))
	for _, path := range paths {
		cPath := C.CString(path)
		status := C.agentSecretBWSMAppendTrustedApplication(applications, cPath)
		C.free(unsafe.Pointer(cPath))
		if status != C.errSecSuccess {
			return keychainNilAccess(), fmt.Errorf("create Bitwarden Secrets Manager Keychain trusted application for %s: %w", path, keychainStatusError("trusted application", status))
		}
	}
	var access C.SecAccessRef
	status := C.agentSecretBWSMCreateAccess(C.CFArrayRef(applications), &access) //nolint:gocritic // cgo macro expansion confuses dupSubExpr.
	if status != C.errSecSuccess {
		return keychainNilAccess(), keychainStatusError("access list", status)
	}
	return access, nil
}

func keychainNilAccess() C.SecAccessRef {
	var access C.SecAccessRef
	return access
}

func keychainStatusError(operation string, status C.OSStatus) error {
	return keychainStatusErrorFromStatus(operation, int(status))
}
