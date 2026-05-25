//go:build darwin && cgo

package gcpauth

/*
#cgo darwin LDFLAGS: -framework CoreFoundation -framework Security
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <stdlib.h>

static CFMutableDictionaryRef agentSecretGCPKeychainQuery(CFStringRef service, CFStringRef account) {
	CFMutableDictionaryRef query = CFDictionaryCreateMutable(
		NULL,
		0,
		&kCFTypeDictionaryKeyCallBacks,
		&kCFTypeDictionaryValueCallBacks
	);
	CFDictionarySetValue(query, kSecClass, kSecClassGenericPassword);
	CFDictionarySetValue(query, kSecAttrService, service);
	CFDictionarySetValue(query, kSecAttrAccount, account);
	return query;
}

static CFMutableDictionaryRef agentSecretGCPKeychainAttrs(CFDataRef data) {
	CFMutableDictionaryRef attrs = CFDictionaryCreateMutable(
		NULL,
		0,
		&kCFTypeDictionaryKeyCallBacks,
		&kCFTypeDictionaryValueCallBacks
	);
	CFDictionarySetValue(attrs, kSecValueData, data);
	CFDictionarySetValue(attrs, kSecAttrAccessible, kSecAttrAccessibleWhenUnlockedThisDeviceOnly);
	return attrs;
}

static CFMutableDictionaryRef agentSecretGCPKeychainAddQuery(CFStringRef service, CFStringRef account, CFDataRef data) {
	CFMutableDictionaryRef query = agentSecretGCPKeychainQuery(service, account);
	CFDictionarySetValue(query, kSecValueData, data);
	CFDictionarySetValue(query, kSecAttrAccessible, kSecAttrAccessibleWhenUnlockedThisDeviceOnly);
	return query;
}

static CFMutableDictionaryRef agentSecretGCPKeychainDataQuery(CFStringRef service, CFStringRef account) {
	CFMutableDictionaryRef query = agentSecretGCPKeychainQuery(service, account);
	CFDictionarySetValue(query, kSecReturnData, kCFBooleanTrue);
	CFDictionarySetValue(query, kSecMatchLimit, kSecMatchLimitOne);
	return query;
}
*/
import "C"

import (
	"context"
	"fmt"
	"unsafe"
)

func keychainGet(ctx context.Context, service string, account string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	serviceRef := cfString(service)
	defer C.CFRelease(C.CFTypeRef(serviceRef))
	accountRef := cfString(account)
	defer C.CFRelease(C.CFTypeRef(accountRef))
	query := C.agentSecretGCPKeychainDataQuery(serviceRef, accountRef)
	defer C.CFRelease(C.CFTypeRef(query))

	var result C.CFTypeRef
	status := C.SecItemCopyMatching(C.CFDictionaryRef(query), &result) //nolint:gocritic // cgo macro expansion confuses dupSubExpr.
	if status == C.errSecItemNotFound {
		return nil, ErrCredentialNotFound
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

	query := C.agentSecretGCPKeychainQuery(serviceRef, accountRef)
	defer C.CFRelease(C.CFTypeRef(query))
	attrs := C.agentSecretGCPKeychainAttrs(dataRef)
	defer C.CFRelease(C.CFTypeRef(attrs))

	addQuery := C.agentSecretGCPKeychainAddQuery(serviceRef, accountRef, dataRef)
	defer C.CFRelease(C.CFTypeRef(addQuery))
	status := C.SecItemAdd(C.CFDictionaryRef(addQuery), nil)
	if status == C.errSecDuplicateItem {
		status = C.SecItemUpdate(C.CFDictionaryRef(query), C.CFDictionaryRef(attrs))
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
	query := C.agentSecretGCPKeychainQuery(serviceRef, accountRef)
	defer C.CFRelease(C.CFTypeRef(query))

	status := C.SecItemDelete(C.CFDictionaryRef(query))
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

func keychainStatusError(operation string, status C.OSStatus) error {
	return fmt.Errorf("GCP Keychain %s failed with OSStatus %d", operation, int(status))
}
