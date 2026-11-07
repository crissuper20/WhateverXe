// EXPERIMENT (-wex-tgl-vp9): VP9 hardware decode for the TGL VA driver.
// The VA driver's decoder factory has no VP9 case. WEX points its skip branch for
// subtype 0x1000 at a stub (tools/vp9/factory-stub.s) that dlopens this library from
// the VA bundle and calls WEXVP9Create(context, config). A non-NULL result is stored in
// the factory's decoder slot like a native decoder; NULL fails the context request, so
// no hardware VP9 session exists.
// For now the decoder only records how the driver drives it: every vtable call is
// logged with its arguments, decode (+0x28) also logs AppleGVA's request, and no GPU
// work is submitted.
// It is created only while the marker file WEXVP9.capture sits next to this library;
// without it every request is declined.
#include <dlfcn.h>
#include <mach/mach.h>
#include <os/log.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static os_log_t wexLog(void) {
	static os_log_t log;
	if (!log) log = os_log_create("org.b00t0x.WhateverXe", "vp9");
	return log;
}

__attribute__((constructor)) static void wexVP9Loaded(void) {
	os_log(wexLog(), "WEXVP9 loaded");
}

// Logs up to 0x60 bytes at a register argument; a value that is not readable memory
// is skipped instead of faulting.
static void peek(int slot, const char *name, uint64_t value) {
	uint8_t bytes[0x60];
	vm_size_t got = 0;
	if (value < 0x1000 || vm_read_overwrite(mach_task_self(), value, sizeof(bytes), (vm_address_t)bytes, &got) != KERN_SUCCESS)
		return;
	char text[sizeof(bytes) * 2 + 1];
	for (size_t i = 0; i < got; ++i) {
		static const char digits[] = "0123456789abcdef";
		text[2 * i] = digits[bytes[i] >> 4];
		text[2 * i + 1] = digits[bytes[i] & 15];
	}
	text[2 * got] = 0;
	os_log(wexLog(), "WEXVP9 slot +0x%x %s=%llx: %{public}s", slot * 8, name, value, text);
}

static void record(int slot, uint64_t self, uint64_t a, uint64_t b, uint64_t c, uint64_t d, uint64_t e) {
	os_log(wexLog(), "WEXVP9 slot +0x%x this=%llx rsi=%llx rdx=%llx rcx=%llx r8=%llx r9=%llx", slot * 8, self, a, b, c, d, e);
	peek(slot, "rsi", a);
	peek(slot, "rdx", b);
	peek(slot, "rcx", c);
}

// Decode (+0x28): rsi is the context's decoder record (+0x18 this decoder) and +0x20
// points at AppleGVA's request. Logs the request fields that Ice Lake's VP9 decoder reads
// (+0x8 bitstream bytes, +0x10 frame header, +0x1248 header length, +0x1250 output
// record, 8 reference records of 0x1258 bytes from +0x1260, ref slots at +0xa520).
static uint8_t request[0xa530];
static void logRequest(uint64_t entry) {
	uint64_t at = 0;
	vm_size_t got = 0;
	if (entry < 0x1000 || vm_read_overwrite(mach_task_self(), entry + 0x20, 8, (vm_address_t)&at, &got) != KERN_SUCCESS)
		return;
	if (at < 0x1000 || vm_read_overwrite(mach_task_self(), at, sizeof(request), (vm_address_t)request, &got) != KERN_SUCCESS
		|| got != sizeof(request)) {
		os_log(wexLog(), "WEXVP9 request %llx unreadable", at);
		return;
	}
	const uint8_t *h = request + 0x10;
	uint32_t bytes, width, height, slots[3];
	uint16_t headerSize;
	uint64_t output, refs[8];
	memcpy(&bytes, request + 0x8, 4);
	memcpy(&headerSize, h + 0x02, 2);
	memcpy(&width, h + 0x4c, 4);
	memcpy(&height, h + 0x50, 4);
	memcpy(&output, request + 0x1250, 8);
	memcpy(slots, request + 0xa520, sizeof(slots));
	for (int i = 0; i < 8; ++i) memcpy(&refs[i], request + 0x1260 + i * 0x1258 + 0x1250, 8);
	os_log(wexLog(), "WEXVP9 request %llx bytes=%u uncomp=%u header_size=%u type=%u show=%u er=%u intra=%u refresh=%02x "
		"reset=%u bias=%u%u%u hp=%u interp=%u refresh_ctx=%u parallel=%u ctx=%u lf=%u sharp=%u q=%u dq=%d/%d/%d seg=%u "
		"log2=%u/%u profile=%u depth=%u size=%ux%u", at, bytes, request[0x1248], headerSize, h[0x05], h[0x06], h[0x07],
		h[0x08], h[0x04], h[0x0d], h[0x12], h[0x13], h[0x14], h[0x15], h[0x16], h[0x17], h[0x18], h[0x19], h[0x1a], h[0x1b],
		h[0x2a], (int8_t)h[0x2b], (int8_t)h[0x2d], (int8_t)h[0x2c], h[0x2e], h[0x40], h[0x44], h[0x48], h[0x49], width, height);
	os_log(wexLog(), "WEXVP9 request %llx output=%llx refs=%llx %llx %llx %llx %llx %llx %llx %llx slots=%u/%u/%u", at, output,
		refs[0], refs[1], refs[2], refs[3], refs[4], refs[5], refs[6], refs[7], slots[0], slots[1], slots[2]);
	peek(5, "request", at);
	peek(5, "header+0x60", at + 0x10 + 0x60);
}

// Same layout as the driver's root decoder base (ctor 0x21756): three pointers, 32
// calloc'ed 8-byte cells at +0x20, a u32 at +0x120. The rest stays zero.
struct Decoder {
	const void *const *vtable;
	uint64_t base[3];
	void *cells[32];
	uint32_t count;
	uint8_t rest[0x400 - 0x124];
};

static void destroy(struct Decoder *self) {
	record(0, (uint64_t)self, 0, 0, 0, 0, 0);
	for (int i = 0; i < 32; ++i) free(self->cells[i]);
	memset(self->cells, 0, sizeof(self->cells));
}

static void destroyAndFree(struct Decoder *self) {
	destroy(self);
	free(self);
}

static int create(struct Decoder *self, uint64_t context, uint64_t config, uint64_t c, uint64_t d, uint64_t e) {
	record(2, (uint64_t)self, context, config, c, d, e);
	return 0;
}

// Other slots keep the driver's base result (0); +0x60 fails.
#define SLOT(n, result) \
	static int slot##n(uint64_t self, uint64_t a, uint64_t b, uint64_t c, uint64_t d, uint64_t e) { \
		record(n, self, a, b, c, d, e); \
		return result; \
	}
SLOT(3, 0) SLOT(4, 0) SLOT(6, 0) SLOT(7, 0) SLOT(8, 0) SLOT(9, 0) SLOT(10, 0) SLOT(11, 0)
SLOT(12, 0x7)
// Decode: log the call and the request, report success so the session keeps feeding
// frames. No GPU work is submitted; the output surfaces stay as AppleGVA allocated them.
static int slot5(uint64_t self, uint64_t a, uint64_t b, uint64_t c, uint64_t d, uint64_t e) {
	record(5, self, a, b, c, d, e);
	logRequest(a);
	return 0;
}

static const void *const vtable[13] = {
	(const void *)destroy, (const void *)destroyAndFree, (const void *)create,
	(const void *)slot3, (const void *)slot4, (const void *)slot5, (const void *)slot6, (const void *)slot7,
	(const void *)slot8, (const void *)slot9, (const void *)slot10, (const void *)slot11, (const void *)slot12,
};

// True while WEXVP9.capture exists next to this library.
static int captureEnabled(void) {
	Dl_info info;
	if (!dladdr((const void *)captureEnabled, &info) || !info.dli_fname) return 0;
	char path[1024];
	strlcpy(path, info.dli_fname, sizeof(path));
	char *slash = strrchr(path, '/');
	if (!slash) return 0;
	strlcpy(slash + 1, "WEXVP9.capture", sizeof(path) - (size_t)(slash + 1 - path));
	return access(path, R_OK) == 0;
}

// config is the factory's request node: +0 type, +8 subtype (0x1000 = VP9),
// +0x20/+0x24 width/height, +0x30 output FourCC, +0x38 next node.
__attribute__((visibility("default"))) void *WEXVP9Create(void *context, void *config) {
	const uint8_t *node = config;
	if (!node) {
		os_log(wexLog(), "WEXVP9Create context=%p config=NULL", context);
		return 0;
	}
	int capture = captureEnabled();
	os_log(wexLog(), "WEXVP9Create context=%p type=%d subtype=0x%llx a=%u b=%u c=%u: %{public}s", context,
		*(const int32_t *)(node + 0x0), *(const unsigned long long *)(node + 0x8),
		*(const uint32_t *)(node + 0x20), *(const uint32_t *)(node + 0x24), *(const uint32_t *)(node + 0x30),
		capture ? "capture decoder" : "declined");
	if (!capture) return 0;
	struct Decoder *self = calloc(1, sizeof(*self));
	if (!self) return 0;
	self->vtable = vtable;
	for (int i = 0; i < 32; ++i) {
		self->cells[i] = calloc(1, 8);
		if (!self->cells[i]) {
			destroyAndFree(self);
			return 0;
		}
	}
	if (create(self, (uint64_t)context, (uint64_t)config, 0, 0, 0)) {
		destroyAndFree(self);
		return 0;
	}
	return self;
}
