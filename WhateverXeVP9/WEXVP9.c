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
// With WEXVP9.batch also present, the decoder creates a hidden native HEVC decoder from
// the same context and uses its Intel HCP/MI/VDENC command builders to build each frame's
// VP9 commands into a plain memory buffer, which is logged and never submitted. Commands
// that need GPU addresses (surface, buffer address, bitstream address) are not built yet.
#include <dlfcn.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <mach/mach.h>
#include <os/log.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "vp9_quant.h"

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
static int logRequest(uint64_t entry) {
	uint64_t at = 0;
	vm_size_t got = 0;
	if (entry < 0x1000 || vm_read_overwrite(mach_task_self(), entry + 0x20, 8, (vm_address_t)&at, &got) != KERN_SUCCESS)
		return 0;
	if (at < 0x1000 || vm_read_overwrite(mach_task_self(), at, sizeof(request), (vm_address_t)request, &got) != KERN_SUCCESS
		|| got != sizeof(request)) {
		os_log(wexLog(), "WEXVP9 request %llx unreadable", at);
		return 0;
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
	return 1;
}

// ---- Batch build through a hidden HEVC decoder (WEXVP9.batch) ----
// Offsets are for the 25G332 AppleIntelTGLGraphicsVADriver (vmaddr 0, so an address is
// the image header plus the offset); the image is used only when its LC_UUID matches.
// Its codec layer is Intel's 2019 media driver (Codechal/MHW).
static const uint8_t vaUUID[16] = {0x00, 0x20, 0x40, 0x00, 0x02, 0x63, 0x40, 0x92,
	0xb4, 0x83, 0xcc, 0x25, 0x44, 0xd2, 0x63, 0x50};
enum {
	HevcSize = 0x2f0,          // factory case 0x800: new(0x2f0)
	HevcCtor = 0x22a740,       // its vtable +0x10 is create(context, node)
	HevcCodechal = 0x2e8,      // CodechalDecodeHevcG12 * after create
	CodechalHcp = 0x48,        // MhwVdboxHcpInterfaceG12 *
	CodechalVdenc = 0x58,      // MhwVdboxVdencInterfaceG12 *
	CodechalMi = 0x60,         // MhwMiInterfaceG12 *
	VdControlState = 0x164570, // MhwMiInterfaceG12::AddMiVdControlStateCmd(mi, cmd, params)
	PmsParamsVtable = 0x758538, // MHW_VDBOX_PIPE_MODE_SELECT_PARAMS_G12 (the builder dynamic_casts)
	HcpPipeModeSelect = 0x78 / 8, // HCP vtable slots
	HcpBsdObject = 0xe8 / 8,
	HcpVp9PicState = 0xf8 / 8,
	HcpVp9SegmentState = 0x108 / 8,
	MiFlushDw = 0x48 / 8,      // MI vtable slot
	VdencPipelineFlush = 0x40 / 8, // VDENC vtable slot
	ModeVp9Vld = 12,           // CODECHAL_DECODE_MODE_VP9VLD
	RefListSize = 0x1300,      // CODEC_REF_LIST is read at +0x1248/+0x124c (width, height)
};

typedef int (*Call2)(void *, void *);
typedef int (*Call3)(void *, void *, void *);
typedef int (*Call4)(void *, void *, void *, void *);

static uint64_t vaBase;

// Finds the VA driver image and checks its UUID; 0 when it is not the expected build.
static uint64_t findVA(void) {
	if (vaBase) return vaBase;
	for (uint32_t i = 0; i < _dyld_image_count(); ++i) {
		const char *name = _dyld_get_image_name(i);
		const char *slash = name ? strrchr(name, '/') : 0;
		if (!slash || strcmp(slash + 1, "AppleIntelTGLGraphicsVADriver")) continue;
		const struct mach_header_64 *mh = (const struct mach_header_64 *)_dyld_get_image_header(i);
		const struct load_command *lc = (const struct load_command *)(mh + 1);
		for (uint32_t c = 0; c < mh->ncmds; ++c, lc = (const struct load_command *)((const uint8_t *)lc + lc->cmdsize)) {
			if (lc->cmd != LC_UUID) continue;
			if (memcmp(((const struct uuid_command *)lc)->uuid, vaUUID, 16)) {
				os_log(wexLog(), "WEXVP9 batch: VA driver UUID differs, batch build off");
				return 0;
			}
			vaBase = (uint64_t)mh;
			return vaBase;
		}
	}
	os_log(wexLog(), "WEXVP9 batch: VA driver image not found");
	return 0;
}

// True when an object's vtable is the VA driver's vtable at offset expect.
static int isA(const void *object, uint64_t expect) {
	return object && *(const uint64_t *)object == vaBase + expect;
}

// C++ class name of an object with a vtable (Itanium ABI: typeinfo at vtable[-1]).
static const char *className(const void *object) {
	if (!object) return "NULL";
	const uint64_t *vt = *(const uint64_t *const *)object;
	const uint64_t *typeinfo = (const uint64_t *)vt[-1];
	return (const char *)typeinfo[1];
}

static void *slot(const void *object, int index) {
	return (void *)(*(const uint64_t *const *)object)[index];
}

// Creates a native HEVC decoder from the VP9 session's context and request node, as the
// factory's 0x800 case does. Returns NULL (and logs why) when anything does not match.
static void *createHevc(void *context, const uint8_t *node) {
	if (!findVA()) return 0;
	if (!((const uint8_t *)context)[0xaaa4]) {
		os_log(wexLog(), "WEXVP9 batch: context has no HEVC support (+0xaaa4 = 0)");
		return 0;
	}
	uint8_t copy[0x40];
	memcpy(copy, node, sizeof(copy));
	*(uint64_t *)(copy + 0x8) = 0x800; // HEVC
	*(uint64_t *)(copy + 0x38) = 0;    // single node
	void *hevc = calloc(1, HevcSize);
	if (!hevc) return 0;
	((void (*)(void *))(vaBase + HevcCtor))(hevc);
	int status = ((Call3)slot(hevc, 2))(hevc, context, copy);
	void *codechal = *(void **)((uint8_t *)hevc + HevcCodechal);
	os_log(wexLog(), "WEXVP9 batch: HEVC create status %d codechal %p %{public}s", status, codechal, className(codechal));
	if (status || !isA(codechal, 0x758400)) {
		((void (*)(void *))slot(hevc, 1))(hevc);
		return 0;
	}
	void *hcp = *(void **)((uint8_t *)codechal + CodechalHcp);
	void *vdenc = *(void **)((uint8_t *)codechal + CodechalVdenc);
	void *mi = *(void **)((uint8_t *)codechal + CodechalMi);
	os_log(wexLog(), "WEXVP9 batch: hcp %{public}s vdenc %{public}s mi %{public}s", className(hcp), className(vdenc),
		className(mi));
	if (!isA(hcp, 0x759818) || !isA(mi, 0x759218) || !vdenc || !strstr(className(vdenc), "MhwVdboxVdencInterfaceG12")) {
		((void (*)(void *))slot(hevc, 1))(hevc);
		return 0;
	}
	return hevc;
}

// Intel MOS_COMMAND_BUFFER as Mos_AddCommand (0x41300) uses it: +0x150 write pointer,
// +0x158 offset, +0x15c bytes remaining; +0x148 is the base. Everything else zero.
struct CommandBuffer {
	uint8_t raw[0x400];
	uint32_t data[1024];
};

static void initCommandBuffer(struct CommandBuffer *cmd) {
	memset(cmd, 0, sizeof(*cmd));
	*(uint32_t **)(cmd->raw + 0x148) = cmd->data;
	*(uint32_t **)(cmd->raw + 0x150) = cmd->data;
	*(int32_t *)(cmd->raw + 0x15c) = sizeof(cmd->data);
}

static uint32_t usedDwords(const struct CommandBuffer *cmd) {
	return (uint32_t)(*(uint32_t *const *)(cmd->raw + 0x150) - cmd->data);
}

static int clampQ(int q) {
	return q < 0 ? 0 : q > 255 ? 255 : q;
}

static int clampLevel(int level) {
	return level < 0 ? 0 : level > 63 ? 63 : level;
}

// Previous frame, for PIC_STATE's motion-vector reuse check.
struct Previous {
	uint8_t flags; // bit0 key frame, bit1 intra only, bit2 shown
	uint32_t width, height;
};

// Builds one frame's commands from AppleGVA's request (layout in logRequest) and logs
// them. Assumes default loop-filter deltas (ref 1/0/-1/-1, mode 0/0), no segmentation
// data and reference frames of the current size: the request fields for those are not
// mapped yet, so each frame logs that.
static void buildBatch(void *hevc, const uint8_t *req, struct Previous *prev, uint32_t frame) {
	void *codechal = *(void **)((uint8_t *)hevc + HevcCodechal);
	void *hcp = *(void **)((uint8_t *)codechal + CodechalHcp);
	void *vdenc = *(void **)((uint8_t *)codechal + CodechalVdenc);
	void *mi = *(void **)((uint8_t *)codechal + CodechalMi);
	const uint8_t *h = req + 0x10;
	uint32_t bytes, width, height, slots[3];
	uint16_t headerSize;
	memcpy(&bytes, req + 0x8, 4);
	memcpy(&headerSize, h + 0x02, 2);
	memcpy(&width, h + 0x4c, 4);
	memcpy(&height, h + 0x50, 4);
	memcpy(slots, req + 0xa520, sizeof(slots));
	uint8_t uncomp = req[0x1248];
	int key = h[0x05] == 0, intra = h[0x08], q = h[0x2a];
	int dqYDc = (int8_t)h[0x2b], dqUvDc = (int8_t)h[0x2d], dqUvAc = (int8_t)h[0x2c];
	int lossless = q == 0 && !dqYDc && !dqUvDc && !dqUvAc;

	// CODEC_VP9_PIC_PARAMS.
	uint8_t pic[0x98] = {0};
	// Apple's build reads +0x2 as the width and +0x0 as the height (vp9-7 log vs iHD).
	*(uint16_t *)(pic + 0x0) = (uint16_t)(height - 1);
	*(uint16_t *)(pic + 0x2) = (uint16_t)(width - 1);
	uint32_t flags = (uint32_t)(h[0x05] & 1) | (uint32_t)(h[0x06] & 1) << 1 | (uint32_t)(h[0x07] & 1) << 2
		| (uint32_t)(intra & 1) << 3 | (slots[0] & 7) << 4 | (uint32_t)(h[0x12] & 1) << 7 | (slots[1] & 7) << 8
		| (uint32_t)(h[0x13] & 1) << 11 | (slots[2] & 7) << 12 | (uint32_t)(h[0x14] & 1) << 15
		| (uint32_t)(h[0x15] & 1) << 16 | (uint32_t)(h[0x16] & 7) << 17 | (uint32_t)(h[0x18] & 1) << 20
		| (uint32_t)(h[0x2e] & 1) << 21 | (uint32_t)(h[0x0d] & 3) << 24 | (uint32_t)(h[0x17] & 1) << 26
		| (uint32_t)(h[0x19] & 3) << 27 | (uint32_t)lossless << 29;
	*(uint32_t *)(pic + 0x4) = flags;
	for (int i = 0; i < 8; ++i) pic[0x8 + 12 * i] = (uint8_t)i; // RefFrameList[i].FrameIdx
	pic[0x74] = h[0x1a];                                          // filter level
	pic[0x75] = h[0x1b];                                          // sharpness
	pic[0x76] = h[0x44];                                          // log2 tile rows
	pic[0x77] = h[0x40];                                          // log2 tile columns
	pic[0x78] = uncomp;
	*(uint16_t *)(pic + 0x7a) = headerSize;
	pic[0x90] = h[0x48];
	pic[0x91] = (uint8_t)(h[0x49] - 8);
	pic[0x92] = 1; // 4:2:0
	pic[0x93] = 1;

	// CODEC_REF_LIST entries: only their width/height are read.
	static uint8_t refList[8][RefListSize];
	void *refs[8];
	for (int i = 0; i < 8; ++i) {
		memcpy(refList[i] + 0x1248, &width, 4);
		memcpy(refList[i] + 0x124c, &height, 4);
		refs[i] = refList[i];
	}
	// MHW_VDBOX_VP9_PIC_STATE.
	uint8_t picState[0x40] = {0};
	*(void **)(picState + 0x0) = pic;
	*(void **)(picState + 0x8) = refs;
	picState[0x10] = prev->flags;
	memcpy(picState + 0x14, &prev->width, 4);
	memcpy(picState + 0x18, &prev->height, 4);

	// Segment 0 (CODEC_VP9_SEG_PARAMS entry, 0x14 bytes): +0 flags (u32), +4 loop filter
	// levels per reference (intra, last, golden, altref) and mode, +0xc the four
	// quantizer scales.
	uint8_t seg[8][0x14] = {{0}};
	static const int refDelta[4] = {1, 0, -1, -1};
	int level = h[0x1a], shift = level >> 5;
	for (int r = 0; r < 4; ++r)
		for (int m = 0; m < 2; ++m) seg[0][0x4 + r * 2 + m] = (uint8_t)(level ? clampLevel(level + refDelta[r] * (1 << shift)) : 0);
	uint16_t scales[4] = {
		(uint16_t)(lossless ? 4 : vp9AcQuant[clampQ(q)]),           // luma AC
		(uint16_t)(lossless ? 4 : vp9DcQuant[clampQ(q + dqYDc)]),   // luma DC
		(uint16_t)(lossless ? 4 : vp9AcQuant[clampQ(q + dqUvAc)]),  // chroma AC
		(uint16_t)(lossless ? 4 : vp9DcQuant[clampQ(q + dqUvDc)]),  // chroma DC
	};
	memcpy(seg[0] + 0xc, scales, sizeof(scales));
	// MHW_VDBOX_VP9_SEGMENT_STATE: +0x8 decode segment data, +0x18 segment id.
	uint8_t segState[0x20] = {0};
	*(void **)(segState + 0x8) = seg;

	// MHW_VDBOX_PIPE_MODE_SELECT_PARAMS_G12: vtable, +0x8 mode, everything else off.
	uint64_t pms[0x20] = {0};
	pms[0] = vaBase + PmsParamsVtable;
	*(uint32_t *)((uint8_t *)pms + 0x8) = ModeVp9Vld;

	uint32_t bsd[2] = {bytes - uncomp, uncomp}; // MHW_VDBOX_HCP_BSD_PARAMS
	uint8_t vdInit[8] = {0}, vdFlush[8] = {0};  // MHW_MI_VD_CONTROL_STATE_PARAMS
	vdInit[2] = 1;                              // initialization
	vdFlush[6] = 1;                             // memory implicit flush
	uint32_t pipeFlush = 0x31;                  // HEVC wait done, VD parser done, HEVC flush
	uint8_t flushDw[0x40] = {0};                // MHW_MI_FLUSH_DW_PARAMS

	static struct CommandBuffer cmd;
	initCommandBuffer(&cmd);
	int s[8];
	s[0] = ((Call3)(vaBase + VdControlState))(mi, &cmd, vdInit);
	s[1] = ((Call3)slot(hcp, HcpPipeModeSelect))(hcp, &cmd, pms);
	s[2] = ((Call4)slot(hcp, HcpVp9SegmentState))(hcp, &cmd, 0, segState);
	s[3] = ((Call4)slot(hcp, HcpVp9PicState))(hcp, &cmd, 0, picState);
	s[4] = ((Call3)slot(hcp, HcpBsdObject))(hcp, &cmd, bsd);
	s[5] = ((Call3)(vaBase + VdControlState))(mi, &cmd, vdFlush);
	s[6] = ((Call3)slot(vdenc, VdencPipelineFlush))(vdenc, &cmd, &pipeFlush);
	s[7] = ((Call3)slot(mi, MiFlushDw))(mi, &cmd, flushDw);
	uint32_t n = usedDwords(&cmd);
	os_log(wexLog(), "WEXVP9 batch frame=%u key=%d size=%ux%u q=%d lf=%d status=%d/%d/%d/%d/%d/%d/%d/%d dwords=%u "
		"(default lf deltas, no segment data, refs at current size)", frame, key, width, height, q, level, s[0], s[1],
		s[2], s[3], s[4], s[5], s[6], s[7], n);
	for (uint32_t at = 0; at < n; at += 16) {
		char text[16 * 9 + 1];
		uint32_t count = n - at < 16 ? n - at : 16;
		for (uint32_t i = 0; i < count; ++i) snprintf(text + 9 * i, 10, "%08x ", cmd.data[at + i]);
		text[9 * count - 1] = 0;
		os_log(wexLog(), "WEXVP9 batch frame=%u +%03x: %{public}s", frame, at, text);
	}
	prev->flags = (uint8_t)(key | (intra & 1) << 1 | (h[0x06] & 1) << 2);
	prev->width = width;
	prev->height = height;
}

// Same layout as the driver's root decoder base (ctor 0x21756): three pointers, 32
// calloc'ed 8-byte cells at +0x20, a u32 at +0x120. The rest stays zero; ours keeps the
// hidden HEVC decoder and per-session batch state there.
struct Hidden {
	void *hevc;
	uint32_t frame;
	struct Previous prev;
};

struct Decoder {
	const void *const *vtable;
	uint64_t base[3];
	void *cells[32];
	uint32_t count;
	uint8_t pad[4];
	struct Hidden hidden;
	uint8_t rest[0x400 - 0x128 - sizeof(struct Hidden)];
};

static void destroy(struct Decoder *self) {
	record(0, (uint64_t)self, 0, 0, 0, 0, 0);
	if (self->hidden.hevc) ((void (*)(void *))slot(self->hidden.hevc, 1))(self->hidden.hevc);
	self->hidden.hevc = 0;
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
	struct Decoder *decoder = (struct Decoder *)self;
	if (logRequest(a) && decoder->hidden.hevc)
		buildBatch(decoder->hidden.hevc, request, &decoder->hidden.prev, decoder->hidden.frame++);
	return 0;
}

static const void *const vtable[13] = {
	(const void *)destroy, (const void *)destroyAndFree, (const void *)create,
	(const void *)slot3, (const void *)slot4, (const void *)slot5, (const void *)slot6, (const void *)slot7,
	(const void *)slot8, (const void *)slot9, (const void *)slot10, (const void *)slot11, (const void *)slot12,
};

// True while the marker file exists next to this library.
static int markerExists(const char *marker) {
	Dl_info info;
	if (!dladdr((const void *)markerExists, &info) || !info.dli_fname) return 0;
	char path[1024];
	strlcpy(path, info.dli_fname, sizeof(path));
	char *slash = strrchr(path, '/');
	if (!slash) return 0;
	strlcpy(slash + 1, marker, sizeof(path) - (size_t)(slash + 1 - path));
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
	int capture = markerExists("WEXVP9.capture");
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
	// A missing hidden decoder only turns the batch log off; the capture decoder stays.
	if (markerExists("WEXVP9.batch")) self->hidden.hevc = createHevc(context, node);
	return self;
}
