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
// VP9 commands into a plain memory buffer, which is logged and never submitted; address
// fields get numbered placeholders.
// With WEXVP9.submit also present, every frame whose log-only build succeeded is built
// again into the OS command buffer with real addresses, submitted to the GPU and waited
// for. The first failure (or a first frame that is not a key frame)
// stops GPU runs for the session; later frames stay log-only.
#include <dlfcn.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <mach/mach.h>
#include <mach/mach_time.h>
#include <os/log.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "vp9_probs.h"
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
		"reset=%u bias=%u%u%u hp=%u interp=%u refresh_ctx=%u parallel=%u ctx=%u lf=%u sharp=%u q=%u dq ydc/uvdc/uvac=%d/%d/%d seg=%u map=%u temporal=%u abs=%u "
		"log2=%u/%u profile=%u depth=%u size=%ux%u", at, bytes, request[0x1248], headerSize, h[0x05], h[0x06], h[0x07],
		h[0x08], h[0x04], h[0x0d], h[0x12], h[0x13], h[0x14], h[0x15], h[0x16], h[0x17], h[0x18], h[0x19], h[0x1a], h[0x1b],
		h[0x2a], (int8_t)h[0x2b], (int8_t)h[0x2c], (int8_t)h[0x2d], h[0x2e], h[0x2f], h[0x37], h[0x3c], h[0x40], h[0x44], h[0x48], h[0x49], width, height);
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
	MiFlushDw = 0x48 / 8,      // MI vtable slots
	MiBatchBufferEnd = 0x18 / 8, // (mi, cmd, 0)
	VdencPipelineFlush = 0x40 / 8, // VDENC vtable slot
	HcpGetVp9BufferSize = 0x58 / 8,
	HcpDecodeSurfaceState = 0x80 / 8,
	HcpPipeBufAddr = 0x90 / 8,
	HcpIndObjBaseAddr = 0x98 / 8,
	PbaParamsVtable = 0x758558, // MHW_VDBOX_PIPE_BUF_ADDR_PARAMS_G12 (dynamic_cast too)
	HevcBindSurface = 0x22b940, // (hevc, IOSurfaceRef, MOS_SURFACE *): fills the resource part
	AllocateBuffer = 0x8a840,  // CodechalDecode::AllocateBuffer(codechal, res, size, name, 0, 0)
	BitstreamId = 0x228df0,    // (context + 0x80, 0): id of the context's bitstream buffer
	CodechalOs = 0x10,         // PMOS_INTERFACE
	OsFreeResource = 0x200,    // MOS_INTERFACE function fields (plain members, no vtable)
	OsGetResourceInfo = 0x210,
	HcpAddResource = 0x2a8,    // MHW interface field: AddResourceToCmd(os, cmd, params)
	OsSetGpuContext = 0xf0,    // (os, context id), as CodechalDecode::Execute calls it
	OsGetCommandBuffer = 0x2a8, // (os, cmd, 0)
	OsReturnCommandBuffer = 0x2c8, // (os, cmd, 0)
	OsSubmitCommandBuffer = 0x2d0, // (os, cmd, null rendering)
	CodechalGpuContext = 0x1e8, // u32 GPU context id
	SendProlog = 0x8de70,      // CodechalDecode::SendPrologWithFrameTracking(codechal, cmd, frame tracking)
	ResLockInit = 0x6c490,     // CodechalResLock(lock, os, resource)
	ResLockMap = 0x6c4c0,      // Lock(lock, 2 = write only): CPU pointer
	ResLockDone = 0x6c620,     // ~CodechalResLock(lock): unlock
	SurfaceInfoPatch = 0x1d,   // MHW_RESOURCE_PARAMS command type of Apple's surface patches
	FormatNV12 = 0x19,         // MOS_FORMAT as the HEVC decoder and SURFACE_STATE use it
	ResourceSize = 0x148,      // MOS_RESOURCE; MOS_SURFACE adds the details up to 0x208
	SurfaceSize = 0x208,
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

// Internal buffers, allocated through the hidden decoder: name, the GetVp9BufferSize type
// (-1 = probability buffer, 0x1000 bytes as iHD) and the PIPE_BUF_ADDR params field that
// points at it (0: chosen per frame). Sized buffers follow the frame size; the four
// probability buffers (one per VP9 frame context) are allocated once and keep their
// contents, as iHD's.
static const struct {
	const char *name;
	int type;
	uint32_t field;
} buffers[] = {
	{"WEXVP9DeblockLine", 0, 0xf0}, {"WEXVP9DeblockTileLine", 1, 0x2f0}, {"WEXVP9DeblockTileColumn", 2, 0x2f8},
	{"WEXVP9MetadataLine", 4, 0x300}, {"WEXVP9MetadataTileLine", 5, 0x308}, {"WEXVP9MetadataTileColumn", 6, 0x310},
	{"WEXVP9SegmentId", 20, 0x3d0}, {"WEXVP9HvdLine", 21, 0x3d8}, {"WEXVP9HvdTile", 22, 0x3e0},
	{"WEXVP9MvTemporal0", 13, 0}, {"WEXVP9MvTemporal1", 13, 0},
	{"WEXVP9Probability0", -1, 0}, {"WEXVP9Probability1", -1, 0}, {"WEXVP9Probability2", -1, 0}, {"WEXVP9Probability3", -1, 0},
};
enum {
	BufferCount = sizeof(buffers) / sizeof(buffers[0]),
	SegmentId = 6,
	MvTemporal0 = 9,   // two, alternating: current and previous (collocated) motion vectors
	Probability0 = 11, // four frame contexts
	PbaCurrentMv = 0x330, PbaCollocatedMv = 0x338, PbaProbability = 0x3c8,
};

struct Hidden {
	void *hevc;
	void *context;
	uint32_t frame;
	int submit, stopped; // WEXVP9.submit present; GPU runs stopped for this session
	struct Previous prev;
	uint32_t slotWidth[8], slotHeight[8]; // picture size held by each reference slot
	uint32_t bufferWidth, bufferHeight; // frame size the buffers were allocated for
	uint8_t allocated[BufferCount];
	uint32_t size[BufferCount];
	// Probability buffer bookkeeping, as iHD's DetermineInternalBufferUpdate.
	uint8_t pendingFull[4], pendingPartial, interSaved, currentMv;
	uint8_t pendingSegProbs[4], segProbs[10]; // tree (7) and prediction (3) probabilities to copy
	uint8_t interProbs[Vp9SegProbOffset - Vp9InterProbOffset];
	uint8_t resource[BufferCount][ResourceSize];
};

static void *osInterface(void *hevc) {
	void *codechal = *(void **)((uint8_t *)hevc + HevcCodechal);
	return *(void **)((uint8_t *)codechal + CodechalOs);
}

// MOS_INTERFACE keeps its functions as plain fields, unlike the C++ objects' vtables.
static void *field(const void *object, uint32_t offset) {
	return *(void *const *)((const uint8_t *)object + offset);
}

// Frees the sized buffers, and the probability buffers too when all is set.
static void freeBuffers(struct Hidden *hidden, int all) {
	void *os = osInterface(hidden->hevc);
	Call2 freeResource = (Call2)field(os, OsFreeResource);
	for (int i = 0; i < BufferCount; ++i) {
		if (buffers[i].type < 0 && !all) continue;
		if (hidden->allocated[i] && freeResource) freeResource(os, hidden->resource[i]);
		hidden->allocated[i] = 0;
		memset(hidden->resource[i], 0, ResourceSize);
	}
	hidden->bufferWidth = hidden->bufferHeight = 0;
}

// CPU pointer to one of our buffers through Apple's CodechalResLock (write-only lock, as
// iHD uses for these updates); NULL when it fails. unmapBuffer ends the lock either way.
static uint8_t *mapBuffer(struct Hidden *hidden, int index, uint8_t lock[0x40]) {
	memset(lock, 0, 0x40);
	((void (*)(void *, void *, void *))(vaBase + ResLockInit))(lock, osInterface(hidden->hevc), hidden->resource[index]);
	return ((uint8_t *(*)(void *, int))(vaBase + ResLockMap))(lock, 2);
}

static void unmapBuffer(uint8_t lock[0x40]) {
	((void (*)(void *))(vaBase + ResLockDone))(lock);
}

// Allocates the internal buffers for this frame size (once per size) with Apple's own
// size helper and allocator. Returns 0 when one fails.
static int allocateBuffers(struct Hidden *hidden, uint32_t width, uint32_t height) {
	if (hidden->bufferWidth == width && hidden->bufferHeight == height) return 1;
	freeBuffers(hidden, 0);
	void *codechal = *(void **)((uint8_t *)hidden->hevc + HevcCodechal);
	void *hcp = *(void **)((uint8_t *)codechal + CodechalHcp);
	int ok = 1;
	for (int i = 0; i < BufferCount; ++i) {
		if (hidden->allocated[i]) continue; // a kept probability buffer
		// MHW_VDBOX_HCP_BUFFER_SIZE_PARAMS: +0 max bit depth, +1 chroma format, +8/+0xc
		// width/height in 64-pixel superblocks, +0x10 size out.
		uint8_t sizeParams[0x20] = {0};
		sizeParams[0] = 8;
		sizeParams[1] = 1;
		uint32_t sbWidth = (width + 63) / 64, sbHeight = (height + 63) / 64, size = 0x1000;
		memcpy(sizeParams + 0x8, &sbWidth, 4);
		memcpy(sizeParams + 0xc, &sbHeight, 4);
		int status = 0;
		if (buffers[i].type >= 0) {
			status = ((int (*)(void *, int, void *))slot(hcp, HcpGetVp9BufferSize))(hcp, buffers[i].type, sizeParams);
			memcpy(&size, sizeParams + 0x10, 4);
		}
		int alloc = status ? -1 : ((int (*)(void *, void *, uint32_t, const char *, int, int))(vaBase + AllocateBuffer))(
			codechal, hidden->resource[i], size, buffers[i].name, 1, 0); // zero filled
		os_log(wexLog(), "WEXVP9 batch: buffer %{public}s type %d size 0x%x size status %d alloc status %d", buffers[i].name,
			buffers[i].type, size, status, alloc);
		if (status || alloc) {
			ok = 0;
			continue;
		}
		hidden->allocated[i] = 1;
		hidden->size[i] = size;
		if (buffers[i].type < 0) { // segment tree and prediction probabilities start at 255, as iHD
			uint8_t lock[0x40];
			uint8_t *data = mapBuffer(hidden, i, lock);
			if (data) memset(data + Vp9SegProbOffset, 255, 10);
			else ok = 0;
			unmapBuffer(lock);
		}
	}
	hidden->bufferWidth = width;
	hidden->bufferHeight = height;
	return ok;
}

// MOS_SURFACE for an IOSurface, as the HEVC decoder builds its output: the resource
// part from HevcBindSurface plus Format_NV12 at +0x18, the details from the OS layer's
// GetResourceInfo. That only copies width (also as pitch), height, format and tiling,
// so the pitch and the chroma row offset come from the IOSurface planes. Also binds the
// surface to the accelerator like HEVC does.
static int surfaceFor(void *hevc, void *ioSurface, uint8_t *surface, const char *what) {
	memset(surface, 0, SurfaceSize);
	if (!ioSurface) return -1;
	int bound = ((int (*)(void *, void *, void *))(vaBase + HevcBindSurface))(hevc, ioSurface, surface);
	static int (*bindAccel)(void *, uint32_t);
	if (!bindAccel) bindAccel = (int (*)(void *, uint32_t))dlsym(RTLD_DEFAULT, "IOSurfaceBindAccel");
	int accel = bindAccel ? bindAccel(ioSurface, *(const uint32_t *)((const uint8_t *)hevc + 0x2c8)) : -1;
	*(uint32_t *)(surface + 0x18) = FormatNV12;
	uint8_t details[SurfaceSize] = {0};
	*(int32_t *)(details + 0x188) = -14; // Format_Invalid
	void *os = osInterface(hevc);
	Call3 getInfo = (Call3)field(os, OsGetResourceInfo);
	if (!getInfo) {
		os_log(wexLog(), "WEXVP9 batch: surface %{public}s: OS GetResourceInfo is NULL, surface skipped", what);
		return -1;
	}
	int info = getInfo(os, surface, details);
	memcpy(surface + ResourceSize, details + ResourceSize, SurfaceSize - ResourceSize);
	static size_t (*rowBytes)(void *, size_t);
	static void *(*planeBase)(void *, size_t);
	if (!rowBytes) rowBytes = (size_t (*)(void *, size_t))dlsym(RTLD_DEFAULT, "IOSurfaceGetBytesPerRowOfPlane");
	if (!planeBase) planeBase = (void *(*)(void *, size_t))dlsym(RTLD_DEFAULT, "IOSurfaceGetBaseAddressOfPlane");
	uint32_t infoPitch, format;
	memcpy(&infoPitch, surface + 0x178, 4);
	memcpy(&format, surface + 0x188, 4);
	size_t pitch = rowBytes ? rowBytes(ioSurface, 0) : 0;
	uintptr_t luma = planeBase ? (uintptr_t)planeBase(ioSurface, 0) : 0, chroma = planeBase ? (uintptr_t)planeBase(ioSurface, 1) : 0;
	uint32_t uOffset = pitch && chroma > luma ? (uint32_t)((chroma - luma) / pitch) : 0;
	if (pitch) *(uint32_t *)(surface + 0x178) = (uint32_t)pitch;
	*(uint32_t *)(surface + 0x1b0) = uOffset;
	os_log(wexLog(), "WEXVP9 batch: surface %{public}s %p bind %d accel %d info %d format %d pitch %u (info %u) "
		"chroma at +0x%llx u-offset %u", what, ioSurface, bound, accel, info, (int)format, (uint32_t)pitch, infoPitch,
		(unsigned long long)(chroma - luma), uOffset);
	return bound || info || !pitch || !uOffset;
}

// Stand-in for HCP's AddResourceToCmd while the batch is only logged. Apple's version
// registers the resource in the accelerator's command stream, which only a real command
// buffer has. This writes a numbered placeholder address (0xadd00000 + n << 12, high
// dword 0xadd) into the command instead, keeping the bits below the address alignment as
// Apple's version does, and the upper bound the same way.
// MHW_RESOURCE_PARAMS: +0x10 command dword, +0x1c alignment bits, +0x24 upper bound
// dword offset, +0x28 size, +0x2c command type. Type 0x1d is Apple's surface-info patch
// (SURFACE_STATE pitch and chroma offset dwords, filled by the kernel at submit); the
// builder writes those fields itself afterwards, so it is only counted.
static uint32_t placeholders, surfacePatches;

static void placeAddress(uint32_t *at, uint32_t shift, uint32_t low) {
	uint32_t mask = shift < 32 ? ~0u << shift : 0;
	at[0] = (at[0] & ~mask) | (low & mask);
	at[1] = 0xadd;
}

static int placeholderAddress(void *os, void *cmd, uint8_t *params) {
	(void)os;
	(void)cmd;
	if (*(uint32_t *)(params + 0x2c) == SurfaceInfoPatch) {
		++surfacePatches;
		return 0;
	}
	uint32_t *at;
	memcpy(&at, params + 0x10, 8);
	uint32_t shift = *(uint32_t *)(params + 0x1c), upper = *(uint32_t *)(params + 0x24);
	uint32_t low = 0xadd00000u + (++placeholders << 12);
	placeAddress(at, shift, low);
	if (upper) placeAddress(at + upper, shift, low + *(uint32_t *)(params + 0x28));
	return 0;
}

// Per-frame buffer state, ported from Intel media-driver's DetermineInternalBufferUpdate,
// ProbBufferPartialUpdatewithDrv and the MV buffer rotation (MIT, LICENSE-media-driver),
// Picks the probability buffer of this frame (context 0 for key, intra-only and
// error-resilient frames), resets or restores its contents as iHD does, copies the
// segmentation tree and prediction probabilities (segProbs, 7 + 3) into it when the map
// is updated, and into other buffers later when they are next used with segmentation,
// zeroes the segment id buffer when iHD does and rotates the motion vector buffers for
// inter frames. Returns the frame context index, -1 when a buffer could not be locked.
static int updateBuffers(struct Hidden *hd, int key, int intra, int errorRes, int resetCtx, int ctx, int scaling,
	int segEnabled, int segUpdateMap, const uint8_t *segProbs) {
	int resetAll = key || errorRes || (resetCtx == 3 && intra);
	int resetSpecified = resetCtx == 2 && intra;
	int index = key || intra || errorRes ? 0 : ctx;
	int full = 0, partial = 0, save = 0, restore = 0, copySeg = 0;
	if (segEnabled && segUpdateMap) {
		copySeg = 1;
		for (int i = 0; i < 4; ++i) hd->pendingSegProbs[i] = (uint8_t)(i != index);
		memcpy(hd->segProbs, segProbs, 7);         // tree, header +0x30
		memcpy(hd->segProbs + 7, segProbs + 8, 3); // prediction, header +0x38 (+0x37 is temporal update)
	} else if (segEnabled && hd->pendingSegProbs[index]) {
		copySeg = 1;
		hd->pendingSegProbs[index] = 0;
	}
	if (resetAll) {
		full = 1;
		hd->pendingPartial = (uint8_t)(key || intra);
		for (int i = 1; i < 4; ++i) hd->pendingFull[i] = 1;
		hd->interSaved = 0;
	} else if (resetSpecified && ctx == 0) {
		full = 1;
		hd->pendingPartial = 1;
		hd->interSaved = 0;
	} else if (resetSpecified || intra) {
		if (resetSpecified) hd->pendingFull[ctx] = 1;
		if (!hd->pendingPartial) {
			if (!hd->interSaved) save = hd->interSaved = 1;
			partial = 1;
		}
	} else if (hd->pendingFull[ctx]) {
		full = 1;
		hd->pendingFull[ctx] = 0;
	} else if (ctx == 0 && hd->pendingPartial) {
		partial = 1;
		hd->pendingPartial = 0;
	} else if (ctx == 0 && hd->interSaved) {
		restore = 1;
		hd->interSaved = 0;
	}
	int ok = 1;
	if (full || partial || save || restore || copySeg) {
		uint8_t lock[0x40];
		uint8_t *data = mapBuffer(hd, Probability0 + index, lock);
		const uint8_t *defaults = key || intra ? vp9KeyProbs : vp9InterProbs;
		if (!data) ok = 0;
		else {
			if (copySeg) memcpy(data + Vp9SegProbOffset, hd->segProbs, sizeof(hd->segProbs));
			if (save) memcpy(hd->interProbs, data + Vp9InterProbOffset, sizeof(hd->interProbs));
			if (full) {
				memcpy(data, defaults, Vp9SegProbOffset);
				memset(data + Vp9SegProbOffset + 10, 0, Vp9ProbSize - Vp9SegProbOffset - 10);
			} else if (partial) {
				for (int r = 0; r < 2; ++r) {
					uint16_t first = vp9PartialReset[key || intra ? 0 : 1][r][0], end = vp9PartialReset[key || intra ? 0 : 1][r][1];
					memcpy(data + first, defaults + first, end - first);
				}
			}
			if (restore) memcpy(data + Vp9InterProbOffset, hd->interProbs, sizeof(hd->interProbs));
		}
		unmapBuffer(lock);
	}
	if (key || scaling || errorRes || intra) {
		uint8_t lock[0x40];
		uint8_t *data = mapBuffer(hd, SegmentId, lock);
		if (data) memset(data, 0, hd->size[SegmentId]);
		else ok = 0;
		unmapBuffer(lock);
	}
	if (!key && !intra) hd->currentMv ^= 1;
	os_log(wexLog(), "WEXVP9 batch: probability context %d full %d partial %d save %d restore %d seg probs %d, current mv %u",
		index, full, partial, save, restore, copySeg, hd->currentMv);
	return ok ? index : -1;
}

// One frame's command parameters, built once and emitted into either buffer.
struct Commands {
	void *hcp, *mi, *vdenc;
	void *vdInit, *pms, *pba, *ind, *segState, *picState, *bsd, *vdFlush, *pipeFlush, *flushDw;
	uint8_t (*surfaceParams)[0x40];
	int surfaces, sv[4], buffersOk, streamOk;
	int segments; // HCP_VP9_SEGMENT_STATE commands: 8 with segmentation, else 1
};

// Emits the frame's commands; s gets the builders' statuses, r the address commands'
// (-1 when skipped).
static void emit(const struct Commands *c, void *cmd, int s[8], int r[6]) {
	for (int i = 0; i < 6; ++i) r[i] = 0;
	s[0] = ((Call3)(vaBase + VdControlState))(c->mi, cmd, c->vdInit);
	s[1] = ((Call3)slot(c->hcp, HcpPipeModeSelect))(c->hcp, cmd, c->pms);
	for (int i = 0; i < c->surfaces; ++i)
		r[i] = c->sv[i] ? -1 : ((Call3)slot(c->hcp, HcpDecodeSurfaceState))(c->hcp, cmd, c->surfaceParams[i]);
	r[4] = c->sv[0] || !c->buffersOk ? -1 : ((Call3)slot(c->hcp, HcpPipeBufAddr))(c->hcp, cmd, c->pba);
	r[5] = !c->streamOk ? -1 : ((Call3)slot(c->hcp, HcpIndObjBaseAddr))(c->hcp, cmd, c->ind);
	s[2] = 0;
	for (int i = 0; i < c->segments && !s[2]; ++i) {
		((uint8_t *)c->segState)[0x18] = (uint8_t)i; // current segment id
		s[2] = ((Call4)slot(c->hcp, HcpVp9SegmentState))(c->hcp, cmd, 0, c->segState);
	}
	s[3] = ((Call4)slot(c->hcp, HcpVp9PicState))(c->hcp, cmd, 0, c->picState);
	s[4] = ((Call3)slot(c->hcp, HcpBsdObject))(c->hcp, cmd, c->bsd);
	s[5] = ((Call3)(vaBase + VdControlState))(c->mi, cmd, c->vdFlush);
	s[6] = ((Call3)slot(c->vdenc, VdencPipelineFlush))(c->vdenc, cmd, c->pipeFlush);
	s[7] = ((Call3)slot(c->mi, MiFlushDw))(c->mi, cmd, c->flushDw);
}

static int allZero(const int *v, int count) {
	for (int i = 0; i < count; ++i)
		if (v[i]) return 0;
	return 1;
}

// One GPU run, in the order Apple's HEVC decode uses: set the GPU context, get the
// command buffer, prolog with frame tracking, the frame's commands, MI_BATCH_BUFFER_END,
// return, submit; then a read lock of the output surface waits for the GPU. A builder
// failing here rewinds the buffer to just after the prolog, so only the prolog and the
// batch end run. Any failure stops GPU runs for the session.
static void submitFrame(struct Hidden *hidden, const struct Commands *c, uint32_t frame, int key, void *output,
	const uint8_t *data) {
	hidden->stopped = 1; // until this run succeeds
	if (!data || (key && (data[1] != 0x49 || data[2] != 0x83 || data[3] != 0x42))) {
		os_log(wexLog(), "WEXVP9 submit frame=%u: bitstream missing or key frame without sync code (%02x %02x %02x %02x), "
			"not submitted", frame, data ? data[0] : 0, data ? data[1] : 0, data ? data[2] : 0, data ? data[3] : 0);
		return;
	}
	void *codechal = *(void **)((uint8_t *)hidden->hevc + HevcCodechal);
	void *os = osInterface(hidden->hevc);
	uint32_t gpuContext;
	memcpy(&gpuContext, (uint8_t *)codechal + CodechalGpuContext, 4);
	int context = ((int (*)(void *, uint32_t))field(os, OsSetGpuContext))(os, gpuContext);
	static uint8_t cmd[0x400];
	memset(cmd, 0, sizeof(cmd));
	int get = context ? -1 : ((int (*)(void *, void *, int))field(os, OsGetCommandBuffer))(os, cmd, 0);
	if (context || get) {
		os_log(wexLog(), "WEXVP9 submit frame=%u: set GPU context %u status %d, get command buffer %d, not submitted", frame,
			gpuContext, context, get);
		return;
	}
	int prolog = ((int (*)(void *, void *, int))(vaBase + SendProlog))(codechal, cmd, 1);
	uint8_t afterProlog[0x10];
	memcpy(afterProlog, cmd + 0x150, sizeof(afterProlog)); // write pointer, offset, remaining
	int st[8], r[6];
	emit(c, cmd, st, r);
	int built = !prolog && allZero(st, 8) && allZero(r, c->surfaces) && !r[4] && !r[5];
	if (!built) memcpy(cmd + 0x150, afterProlog, sizeof(afterProlog));
	int end = ((Call3)slot(c->mi, MiBatchBufferEnd))(c->mi, cmd, 0);
	uint32_t used;
	memcpy(&used, cmd + 0x158, 4);
	((int (*)(void *, void *, int))field(os, OsReturnCommandBuffer))(os, cmd, 0);
	int submit = ((int (*)(void *, void *, int))field(os, OsSubmitCommandBuffer))(os, cmd, 0);
	static int (*surfaceLock)(void *, uint32_t, uint32_t *), (*surfaceUnlock)(void *, uint32_t, uint32_t *);
	if (!surfaceLock) surfaceLock = (int (*)(void *, uint32_t, uint32_t *))dlsym(RTLD_DEFAULT, "IOSurfaceLock");
	if (!surfaceUnlock) surfaceUnlock = (int (*)(void *, uint32_t, uint32_t *))dlsym(RTLD_DEFAULT, "IOSurfaceUnlock");
	uint64_t start = mach_absolute_time();
	int wait = surfaceLock && surfaceUnlock ? surfaceLock(output, 1, NULL) : -1; // kIOSurfaceLockReadOnly
	if (!wait) surfaceUnlock(output, 1, NULL);
	mach_timebase_info_data_t timebase;
	mach_timebase_info(&timebase);
	uint64_t waited = (mach_absolute_time() - start) * timebase.numer / timebase.denom / 1000;
	if (built && !submit && !wait) hidden->stopped = 0;
	os_log(wexLog(), "WEXVP9 submit frame=%u: context %u prolog %d status=%d/%d/%d/%d/%d/%d/%d/%d surface/addr/ind=%d/%d/%d "
		"%{public}s end %d bytes %u submit %d wait %d (%llu us)", frame, gpuContext, prolog, st[0], st[1], st[2], st[3], st[4], st[5],
		st[6], st[7], r[0], r[4], r[5], built ? "frame built" : "BUILD FAILED, prolog only", end, used, submit, wait,
		(unsigned long long)waited);
}

// Builds one frame's commands from AppleGVA's request (layout in logRequest) and logs
// them. Reference sizes are tracked per slot from refresh_frame_flags.
static void buildBatch(struct Hidden *hidden, const uint8_t *req) {
	void *hevc = hidden->hevc;
	struct Previous *prev = &hidden->prev;
	uint32_t frame = hidden->frame++;
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
	// Delta q order as Ice Lake's VP9 decoder reads it (0x208380): y dc, uv dc, uv ac.
	int dqYDc = (int8_t)h[0x2b], dqUvDc = (int8_t)h[0x2c], dqUvAc = (int8_t)h[0x2d];
	int segEnabled = h[0x2e] & 1;
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
		| (uint32_t)segEnabled << 21 | (uint32_t)(h[0x37] & 1) << 22 | (uint32_t)(h[0x2f] & 1) << 23 | (uint32_t)(h[0x0d] & 3) << 24 | (uint32_t)(h[0x17] & 1) << 26
		| (uint32_t)(h[0x19] & 3) << 27 | (uint32_t)lossless << 29;
	*(uint32_t *)(pic + 0x4) = flags;
	for (int i = 0; i < 8; ++i) pic[0x8 + 12 * i] = (uint8_t)i; // RefFrameList[i].FrameIdx
	pic[0x74] = h[0x1a];                                          // filter level
	pic[0x75] = h[0x1b];                                          // sharpness
	pic[0x76] = h[0x44];                                          // log2 tile rows
	pic[0x77] = h[0x40];                                          // log2 tile columns
	pic[0x78] = uncomp;
	*(uint16_t *)(pic + 0x7a) = headerSize;
	memcpy(pic + 0x7c, h + 0x30, 7);                              // segmentation tree probabilities
	memcpy(pic + 0x83, h + 0x38, 3);                              // segmentation prediction probabilities
	pic[0x90] = h[0x48];
	pic[0x91] = (uint8_t)(h[0x49] - 8);
	pic[0x92] = 1; // 4:2:0
	pic[0x93] = 1;

	// CODEC_REF_LIST entries: only their width/height are read.
	static uint8_t refList[8][RefListSize];
	void *refs[8];
	for (int i = 0; i < 8; ++i) {
		memcpy(refList[i] + 0x1248, hidden->slotWidth[i] ? &hidden->slotWidth[i] : &width, 4);
		memcpy(refList[i] + 0x124c, hidden->slotHeight[i] ? &hidden->slotHeight[i] : &height, 4);
		refs[i] = refList[i];
	}
	// MHW_VDBOX_VP9_PIC_STATE.
	uint8_t picState[0x40] = {0};
	*(void **)(picState + 0x0) = pic;
	*(void **)(picState + 0x8) = refs;
	picState[0x10] = prev->flags;
	memcpy(picState + 0x14, &prev->width, 4);
	memcpy(picState + 0x18, &prev->height, 4);

	// CODEC_VP9_SEG_PARAMS, one 0x14-byte entry per segment: +0 flags (bit 0 reference
	// enabled, bits 1-2 reference, bit 3 skip), +4 loop filter levels per reference (intra,
	// last, golden, altref) and mode, +0xc luma AC/DC and chroma AC/DC quantizer scales.
	// Header features per segment s, as Ice Lake's VP9 decoder reads them (0x208380): enabled
	// flags at +0xad+4s (alt q, alt lf, reference, skip), signed 16-bit data at +0xce+8s (alt
	// q, alt lf, reference); +0x3c absolute values instead of deltas.
	// Quantizer index and loop filter levels as libvpx computes them (vp9_get_qindex,
	// vp9_loop_filter_frame_init): header +0x1c deltas enabled, +0x22 four reference deltas,
	// +0x28 two mode deltas (signed). Intra uses its reference delta only.
	uint8_t seg[8][0x14] = {{0}};
	int level = h[0x1a], deltas = h[0x1c], absolute = h[0x3c];
	for (int id = 0; id < 8; ++id) {
		const uint8_t *on = h + 0xad + 4 * id;
		int16_t data[3];
		memcpy(data, h + 0xce + 8 * id, sizeof(data));
		int segQ = segEnabled && on[0] ? clampQ(absolute ? data[0] : q + data[0]) : q;
		int segLevel = segEnabled && on[1] ? clampLevel(absolute ? data[1] : level + data[1]) : level;
		int scale = 1 << (segLevel >> 5);
		for (int r = 0; r < 4; ++r)
			for (int m = 0; m < 2; ++m) {
				int v = segLevel + (deltas ? (int8_t)h[0x22 + r] * scale + (r ? (int8_t)h[0x28 + m] * scale : 0) : 0);
				seg[id][0x4 + r * 2 + m] = (uint8_t)(level ? clampLevel(v) : 0);
			}
		// iHD: a reference feature on a key or intra-only frame means intra.
		int refOn = segEnabled && on[2], reference = refOn && !key && !intra ? data[2] & 3 : 0;
		uint16_t segFlags = (uint16_t)(refOn | reference << 1 | (segEnabled && on[3]) << 3);
		uint16_t scales[4] = {
			(uint16_t)vp9AcQuant[segQ],                  // luma AC
			(uint16_t)vp9DcQuant[clampQ(segQ + dqYDc)],  // luma DC
			(uint16_t)vp9AcQuant[clampQ(segQ + dqUvAc)], // chroma AC
			(uint16_t)vp9DcQuant[clampQ(segQ + dqUvDc)], // chroma DC
		};
		memcpy(seg[id], &segFlags, 2);
		memcpy(seg[id] + 0xc, scales, sizeof(scales));
	}
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

	// Output and reference surfaces (AppleGVA's IOSurfaces at +0x1250 of the request and
	// of each reference record), internal buffers and the context's bitstream buffer.
	int inter = !key && !intra;
	static uint8_t surfaces[4][SurfaceSize]; // current, LAST, GOLDEN, ALTREF
	int sv[4] = {0, 0, 0, 0};
	void *ioSurface;
	memcpy(&ioSurface, req + 0x1250, 8);
	void *output = ioSurface;
	sv[0] = surfaceFor(hevc, ioSurface, surfaces[0], "output");
	for (int r = 0; inter && r < 3; ++r) {
		memcpy(&ioSurface, req + 0x1260 + slots[r] * 0x1258 + 0x1250, 8);
		sv[1 + r] = surfaceFor(hevc, ioSurface, surfaces[1 + r], r == 0 ? "last" : r == 1 ? "golden" : "altref");
	}
	int buffersOk = allocateBuffers(hidden, width, height);
	uint8_t *context = hidden->context;
	uint32_t streamSize;
	memcpy(&streamSize, context + 0x88, 4);
	uint8_t stream[ResourceSize] = {0}; // MOS_RESOURCE built as the HEVC decoder does
	*(uint32_t *)(stream + 0x10) = streamSize;
	*(uint32_t *)(stream + 0x18) = 0x3e; // Format_Buffer
	*(uint32_t *)(stream + 0x1c) = 4;
	*(uint32_t *)(stream + 0x38) = ((uint32_t (*)(void *, int))(vaBase + BitstreamId))(context + 0x80, 0);
	memcpy(stream + 0x50, context + 0x90, 8);
	// The request's +0x0 points at this frame's data inside the context's buffer (frames of
	// a superframe follow each other); the offset from the buffer start goes to IND_OBJ, as
	// Ice Lake's VP9 decoder computes it.
	const uint8_t *data, *base;
	memcpy(&data, req, 8);
	memcpy(&base, context + 0x90, 8);
	uint64_t offset = data >= base ? (uint64_t)(data - base) : ~0ull;
	int streamOk = data && base && offset + bytes <= streamSize;
	os_log(wexLog(), "WEXVP9 batch frame=%u bitstream context size %u request bytes %u offset %llu id %u buffers %d", frame,
		streamSize, bytes, (unsigned long long)offset, *(uint32_t *)(stream + 0x38), buffersOk);

	// MHW_VDBOX_SURFACE_PARAMS: +0 mode, +8 surface, +0x11 chroma type (1 = 4:2:0), +0x12
	// surface id (0 decoded, 2 LAST, 3 GOLDEN, 4 ALTREF).
	uint8_t surfaceParams[4][0x40] = {{0}};
	static const uint8_t surfaceIds[4] = {0, 2, 3, 4};
	for (int i = 0; i < 4; ++i) {
		*(uint32_t *)surfaceParams[i] = ModeVp9Vld;
		*(void **)(surfaceParams[i] + 0x8) = surfaces[i];
		surfaceParams[i][0x11] = 1;
		surfaceParams[i][0x12] = surfaceIds[i];
	}
	// MHW_VDBOX_PIPE_BUF_ADDR_PARAMS_G12: vtable, +8 mode, +0x10 decoded surface, +0x68
	// eight references (key frame: all the current surface; inter: LAST, GOLDEN, ALTREF,
	// then the current surface, as iHD), internal buffers.
	static uint64_t pba[0x100];
	memset(pba, 0, sizeof(pba));
	pba[0] = vaBase + PbaParamsVtable;
	*(uint32_t *)((uint8_t *)pba + 0x8) = ModeVp9Vld;
	*(void **)((uint8_t *)pba + 0x10) = surfaces[0];
	for (int i = 0; i < 8; ++i) *(void **)((uint8_t *)pba + 0x68 + 8 * i) = inter && i < 3 ? surfaces[1 + i] : surfaces[0];
	for (int i = 0; i < BufferCount; ++i)
		if (hidden->allocated[i] && buffers[i].field) *(void **)((uint8_t *)pba + buffers[i].field) = hidden->resource[i];
	int scaling = prev->width != width || prev->height != height;
	int probIndex = buffersOk ? updateBuffers(hidden, key, intra, h[0x07] & 1, h[0x0d] & 3, h[0x19] & 3, scaling, segEnabled,
		h[0x2f] & 1, h + 0x30) : -1;
	if (probIndex >= 0) *(void **)((uint8_t *)pba + PbaProbability) = hidden->resource[Probability0 + probIndex];
	if (inter) { // iHD: current MV buffer for inter frames, the previous one when that frame was inter too
		*(void **)((uint8_t *)pba + PbaCurrentMv) = hidden->resource[MvTemporal0 + hidden->currentMv];
		if (!(prev->flags & 3)) *(void **)((uint8_t *)pba + PbaCollocatedMv) = hidden->resource[MvTemporal0 + (hidden->currentMv ^ 1)];
	}
	// MHW_VDBOX_IND_OBJ_BASE_ADDR_PARAMS: +0 mode, +8 bitstream, +0x10 size, +0x14 offset.
	uint8_t ind[0x80] = {0};
	*(uint32_t *)ind = ModeVp9Vld;
	*(void **)(ind + 0x8) = stream;
	*(uint32_t *)(ind + 0x10) = bytes;
	*(uint32_t *)(ind + 0x14) = streamOk ? (uint32_t)offset : 0;

	static struct CommandBuffer cmd;
	initCommandBuffer(&cmd);
	void **addResource = (void **)((uint8_t *)hcp + HcpAddResource);
	void *appleAddResource = *addResource;
	*addResource = (void *)placeholderAddress;
	placeholders = surfacePatches = 0;
	struct Commands c = {hcp, mi, vdenc, vdInit, pms, pba, ind, segState, picState, bsd, vdFlush, &pipeFlush, flushDw,
		surfaceParams, inter ? 4 : 1, {sv[0], sv[1], sv[2], sv[3]}, buffersOk, streamOk, segEnabled ? 8 : 1};
	int s[8], r[6];
	emit(&c, &cmd, s, r);
	*addResource = appleAddResource;
	uint32_t n = usedDwords(&cmd);
	os_log(wexLog(), "WEXVP9 batch frame=%u key=%d size=%ux%u q=%d lf=%d status=%d/%d/%d/%d/%d/%d/%d/%d "
		"surface/addr/ind=%d/%d/%d/%d/%d/%d addresses %u surface patches %u dwords=%u seg=%d map=%d temporal=%d abs=%d (refs at slot sizes)", frame,
		key, width, height, q, level, s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7], r[0], r[1], r[2], r[3], r[4], r[5], placeholders, surfacePatches, n,
		segEnabled, h[0x2f] & 1, h[0x37] & 1, absolute);
	for (uint32_t at = 0; at < n; at += 16) {
		char text[16 * 9 + 1];
		uint32_t count = n - at < 16 ? n - at : 16;
		for (uint32_t i = 0; i < count; ++i) snprintf(text + 9 * i, 10, "%08x ", cmd.data[at + i]);
		text[9 * count - 1] = 0;
		os_log(wexLog(), "WEXVP9 batch frame=%u +%03x: %{public}s", frame, at, text);
	}
	if (hidden->submit && !hidden->stopped) {
		const char *why = !allZero(s, 8) || !allZero(r, 6) ? "log-only build failed" : probIndex < 0 ? "buffer update failed"
			: frame == 0 && !key ? "first frame is not a key frame" : 0;
		if (why) {
			hidden->stopped = 1;
			os_log(wexLog(), "WEXVP9 submit frame=%u: %{public}s, GPU runs stopped for this session", frame, why);
		} else submitFrame(hidden, &c, frame, key, output, data);
	}
	prev->flags = (uint8_t)(key | (intra & 1) << 1 | (h[0x06] & 1) << 2);
	prev->width = width;
	prev->height = height;
	for (int i = 0; i < 8; ++i)
		if (key || (h[0x04] >> i & 1)) {
			hidden->slotWidth[i] = width;
			hidden->slotHeight[i] = height;
		}
}

// Same layout as the driver's root decoder base (ctor 0x21756): three pointers, 32
// calloc'ed 8-byte cells at +0x20, a u32 at +0x120. The rest stays zero; ours keeps the
// hidden HEVC decoder and per-session batch state there (struct Hidden).

struct Decoder {
	const void *const *vtable;
	uint64_t base[3];
	void *cells[32];
	uint32_t count;
	uint8_t rest[0x400 - 0x124]; // zero, as the driver's base
	struct Hidden hidden;         // ours, past the base layout
};

static void destroy(struct Decoder *self) {
	record(0, (uint64_t)self, 0, 0, 0, 0, 0);
	if (self->hidden.hevc) {
		freeBuffers(&self->hidden, 1);
		((void (*)(void *))slot(self->hidden.hevc, 1))(self->hidden.hevc);
	}
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
		buildBatch(&decoder->hidden, request);
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
	if (markerExists("WEXVP9.batch")) {
		self->hidden.hevc = createHevc(context, node);
		self->hidden.context = context;
		self->hidden.submit = markerExists("WEXVP9.submit");
		os_log(wexLog(), "WEXVP9 batch: GPU run of the first key frame %{public}s", self->hidden.submit ? "ON (WEXVP9.submit)" : "off");
	}
	return self;
}
