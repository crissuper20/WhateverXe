// EXPERIMENT (-wex-tgl-vp9): VP9 hardware decode for the TGL VA driver.
// The VA driver's decoder factory has no VP9 case. WEX points its skip branch for
// subtype 0x1000 at a stub (tools/vp9/factory-stub.s) that dlopens this library from
// the VA bundle and calls WEXVP9Create(context, config). A non-NULL result continues on
// the native skip path; NULL fails the context request, so no hardware VP9 session exists.
// For now it reports each request and declines it (NULL).
#include <os/log.h>
#include <stdint.h>

static os_log_t wexLog(void) {
	static os_log_t log;
	if (!log) log = os_log_create("org.b00t0x.WhateverXe", "vp9");
	return log;
}

__attribute__((constructor)) static void wexVP9Loaded(void) {
	os_log(wexLog(), "WEXVP9 loaded");
}

// config is the factory's request node: +0 type, +8 subtype (0x1000 = VP9),
// +0x20/+0x24/+0x30 the values native cases pass to their setup, +0x38 next node.
__attribute__((visibility("default"))) void *WEXVP9Create(void *context, void *config) {
	const uint8_t *node = config;
	if (!node) {
		os_log(wexLog(), "WEXVP9Create context=%p config=NULL", context);
		return 0;
	}
	os_log(wexLog(), "WEXVP9Create context=%p type=%d subtype=0x%llx a=%u b=%u c=%u: declined", context,
		*(const int32_t *)(node + 0x0), *(const unsigned long long *)(node + 0x8),
		*(const uint32_t *)(node + 0x20), *(const uint32_t *)(node + 0x24), *(const uint32_t *)(node + 0x30));
	return 0;
}
