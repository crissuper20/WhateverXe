// Copyright (c) 2026 b00t0x. BSD-3-Clause.
#pragma once
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "kern_gen12_dither.hpp"

// impostor.dylib bridges Metal's Tahoe descriptors to the older driver layout,
// but only after comparing kern.osversion with 25G241. Without the bridge the
// driver reads BGRA8Unorm as format 5120 and WindowServer crashes on its first
// blended draw. Both comparisons are immediates on the image's first page. The
// bridge's own class, size, encoding and prologue guards stay in force.
namespace TahoeDescriptor {
struct Gate {size_t offset; uint8_t code[20];};
constexpr size_t buildPrefix=1, buildSuffix=9; // Immediates: "25G2" at +0 and "241\0" at +3 of the build.
constexpr char supportedBuild[]="25G332";
constexpr Gate gates[] {
 {0xaea,{0xb8,0x32,0x35,0x47,0x32,0x33,0x45,0xd0,0xb9,0x32,0x34,0x31,0x00,0x33,0x4d,0xd3,0x09,0xc1,0x75,0xa9}}, // Archive
 {0xdb7,{0xb8,0x32,0x35,0x47,0x32,0x33,0x45,0xb0,0xb9,0x32,0x34,0x31,0x00,0x33,0x4d,0xb3,0x09,0xc1,0x75,0xb4}}, // Descriptor
};

// vn_getpath may expose the Data mount rather than its firmlink.
inline const char *stripData(const char *path) {
 constexpr const char data[]="/System/Volumes/Data";
 return strncmp(path,data,sizeof(data)-1) ? path : path+sizeof(data)-1;
}
inline bool image(const char *path) {
 return path && !strcmp(stripData(path),"/Library/GPUBundles/AppleIntelTGLGraphicsMTLDriver.bundle/Contents/MacOS/impostor.dylib");
}
inline bool admitted(const void *page,uint64_t offset,bool validated,bool tainted,const char *build) {
 if(offset || !page || !validated || tainted || !build || strcmp(build,supportedBuild))return false;
 for(const auto &gate:gates)
  if(memcmp(static_cast<const uint8_t *>(page)+gate.offset,gate.code,sizeof(gate.code)))return false;
 return true;
}
inline void apply(uint8_t *page) {
 for(const auto &gate:gates) {
  memcpy(page+gate.offset+buildPrefix,supportedBuild,4);
  memcpy(page+gate.offset+buildSuffix,supportedBuild+3,4);
 }
}

// TGLVA calls _exit(90) in any process loading it unless SystemVersion's build
// equals this literal. Its donor vtable and patch guards stay in force.
constexpr uint64_t videoPage=0x10000;
constexpr size_t videoOffset=0xd60, videoBuild=0x13;
constexpr uint8_t videoCode[] {
 0x63,0x20,0x77,0x69,0x74,0x6e,0x65,0x73,0x73,0x20,0x6d,0x69,0x73,0x6d,0x61,0x74,
 0x63,0x68,0x00,0x32,0x35,0x47,0x32,0x34,0x31,0x00,0x32,0x35,0x2e,0x36,0x2e,0x30,
 0x00,0x6b,0x65,0x72,0x6e,0x2e,0x6f,0x73,0x72,0x65,0x6c,0x65,0x61,0x73,0x65,0x00,
};
inline bool videoImage(const char *path) {
 return path && !strcmp(stripData(path),"/Library/GPUBundles/AppleIntelTGLGraphicsVADriver.bundle/Contents/MacOS/TGLVA");
}
inline bool videoAdmitted(const void *page,uint64_t offset,bool validated,bool tainted,const char *build) {
 return offset==videoPage && page && validated && !tainted && build && !strcmp(build,supportedBuild) &&
  !memcmp(static_cast<const uint8_t *>(page)+videoOffset,videoCode,sizeof(videoCode));
}
inline void applyVideo(uint8_t *page) {
 memcpy(page+videoOffset+videoBuild,supportedBuild,sizeof(supportedBuild)-1);
}

// Video pixel transfer dereferences engine slot 0 of a three-slot table in which
// only slot 2 is ever created, killing WebKit's GPU process. Slots 0 and 1 are
// the missing stages, so no hardware transfer can complete. Report failure while
// the engine is created, keeping slot 2 for teardown, which starts at slot 1.
struct DriverSite {uint64_t page; size_t offset; uint8_t size; uint8_t before[21]; uint8_t after[21];};
constexpr DriverSite driverSites[] {
 {0x1b1000,0xd40,21,
  {0x48,0x89,0x81,0x20,0x09,0x00,0x00,0x48,0x83,0xb9,0x20,0x09,0x00,0x00,0x00,0x0f,0x84,0x0a,0x00,0x00,0x00},
  {0x48,0x89,0x81,0x20,0x09,0x00,0x00,0xe9,0x13,0x00,0x00,0x00,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90}},
 {0x132000,0xa09,16,
  {0xe9,0x00,0x00,0x00,0x00,0xc7,0x45,0xe8,0x00,0x00,0x00,0x00,0x83,0x7d,0xe8,0x03},
  {0xe9,0x00,0x00,0x00,0x00,0xc7,0x45,0xe8,0x01,0x00,0x00,0x00,0x83,0x7d,0xe8,0x03}},
};
inline bool driverImage(const char *path) {
 return path && !strcmp(stripData(path),"/Library/GPUBundles/AppleIntelTGLGraphicsVADriver.bundle/Contents/MacOS/AppleIntelTGLGraphicsVADriver");
}
inline const DriverSite *driverSite(const void *page,uint64_t offset,bool validated,bool tainted,const char *build) {
 if(!page || !validated || tainted || !build || strcmp(build,supportedBuild))return nullptr;
 for(const auto &site:driverSites)
  if(site.page==offset && !memcmp(static_cast<const uint8_t *>(page)+site.offset,site.before,site.size))return &site;
 return nullptr;
}
inline void applyDriver(uint8_t *page,const DriverSite &site) {memcpy(page+site.offset,site.after,site.size);}

// EXPERIMENT (-wex-tgl-gen12-dither): AVD_VideoProcessingContext kernel 3 dithers luma for
// 420v output. It is Gen11 code, which Gen12 misreads, so its threads never end and
// the render engine hangs. Replace it in place with our own Gen12 kernel. The slot is
// 2992 bytes at 0x761f00 in __data and spans two pages; each part is admitted only
// when its original bytes have the expected FNV-1a hash.
struct BlobPart {uint64_t page; size_t offset; size_t size; size_t source; uint64_t hash;};
constexpr BlobPart ditherParts[] {
 {0x761000,0xf00,0x100,0,0xbcfd7ab2e131478cULL},
 {0x762000,0,0xab0,0x100,0x98b170911f579f73ULL},
};
inline uint64_t fnv1a(const uint8_t *bytes,size_t size) {
 uint64_t hash=0xcbf29ce484222325ULL;
 for(size_t i=0;i<size;++i) {hash^=bytes[i];hash*=0x100000001b3ULL;}
 return hash;
}
inline const BlobPart *ditherPart(const void *page,uint64_t offset,bool validated,bool tainted,const char *build) {
 if(!page || !validated || tainted || !build || strcmp(build,supportedBuild))return nullptr;
 for(const auto &part:ditherParts)
  if(part.page==offset && fnv1a(static_cast<const uint8_t *>(page)+part.offset,part.size)==part.hash)return &part;
 return nullptr;
}
inline void applyDither(uint8_t *page,const BlobPart &part) {memcpy(page+part.offset,gen12Dither420v+part.source,part.size);}

// EXPERIMENT (-wex-tgl-vp9): the decoder factory has no VP9 case; subtype 0x1000 falls to
// the skip branch at 0x144e2 (jne 0x149a5). Point that branch at a stub in the header pad
// (0xC70, inside the zero gap 0xC6E-0xD2F) that calls WEXVP9Create from
// @loader_path/WEXVP9.dylib. A decoder goes into the decoder slot and continues on the
// native success path (0x149a8); no library, no symbol or a NULL result fails through
// the factory's error exit 0x15072 (ebx = 1). Each page is admitted
// only when its whole original content has the expected FNV-1a hash, so the branch can
// never be patched without the matching stub page of the same binary.
// Stub source: tools/vp9/factory-stub.s; bytes: tools/vp9/gen-stub.py.
struct PagePatch {uint64_t page; uint64_t hash; size_t offset; size_t size; const uint8_t *bytes;};
constexpr uint8_t vp9Stub[] {
 0x48,0x3d,0x00,0x10,0x00,0x00,0x0f,0x85,0x29,0x3d,0x01,0x00,0x49,0x8b,0x01,0x4a,
 0x83,0x3c,0xf8,0x00,0x0f,0x85,0x1b,0x3d,0x01,0x00,0x56,0x41,0x51,0x41,0x50,0x57,
 0x52,0x51,0x41,0x52,0x41,0x53,0x48,0x8d,0x3d,0x59,0x00,0x00,0x00,0xbe,0x02,0x00,
 0x00,0x00,0xe8,0xd9,0xd6,0x23,0x00,0x48,0x85,0xc0,0x74,0x20,0x48,0x89,0xc7,0x48,
 0x8d,0x35,0x5a,0x00,0x00,0x00,0xe8,0xcb,0xd6,0x23,0x00,0x48,0x85,0xc0,0x74,0x0c,
 0x48,0x8b,0xbd,0x98,0xfe,0xff,0xff,0x4c,0x89,0xf6,0xff,0xd0,0x41,0x5b,0x41,0x5a,
 0x59,0x5a,0x5f,0x41,0x58,0x41,0x59,0x5e,0x48,0x85,0xc0,0x74,0x0f,0x49,0x8b,0x09,
 0x4a,0x89,0x04,0xf9,0x45,0x31,0xe4,0xe9,0xbc,0x3c,0x01,0x00,0xbb,0x01,0x00,0x00,
 0x00,0xe9,0x7c,0x43,0x01,0x00,0x40,0x6c,0x6f,0x61,0x64,0x65,0x72,0x5f,0x70,0x61,
 0x74,0x68,0x2f,0x57,0x45,0x58,0x56,0x50,0x39,0x2e,0x64,0x79,0x6c,0x69,0x62,0x00,
 0x57,0x45,0x58,0x56,0x50,0x39,0x43,0x72,0x65,0x61,0x74,0x65,0x00,
};
constexpr uint64_t vp9Cave=0xc70, vp9CaveEnd=0xd30, vp9Branch=0x144e2;
// jne rel32 from the branch's next instruction (0x144e8) to the stub.
constexpr uint8_t vp9Jump[] {0x0f,0x85,
 uint8_t(vp9Cave-(vp9Branch+6)),uint8_t((vp9Cave-(vp9Branch+6))>>8),uint8_t((vp9Cave-(vp9Branch+6))>>16),uint8_t((vp9Cave-(vp9Branch+6))>>24)};
// AppleGVA asks for a decode context only among the configs the driver advertises. The MFX
// engine's lists (built from 0x754e20 at 0x2bd0c) have no type 1 / subtype 0x1000 entry, so
// VP9 context creation fails before the factory. ICL's MFX list 13 is that entry. Rewrite
// TGL's type 1 / 0x40 descriptor (MFX list 4, 0x78bd30; an MPEG-era subtype AppleGVA has no
// flow for) into ICL's VP9 descriptor, in TGL's layout (ICL has 8 more bytes after +0x18):
// subtype 0x1000, rate 0x2d000000, input braw, outputs NV12 x420 420f xf20 (flags 5).
// The descriptor is plain data. AppleGVA requests VP9 as that one node alone, and the
// factory needs a list that ends with it too, but list 4 continues with 16/1 and the
// builder reads exactly 13 lists. So MFX list 6 (a lone 16/1 that no decode requests;
// H.264 and HEVC were traced) points at the descriptor instead. Slot 0x754eb0 is rebased,
// so it keeps holding an image pointer and dyld slides it as before.
constexpr uint64_t vp9Descriptor=0x78bd30;
constexpr uint64_t vp9ListSlot=0x754eb0, vp9ListPage=vp9ListSlot&~0xfffULL, vp9ListHash=0x89ed4abf7988dd93ULL;
constexpr uint8_t vp9ListPointer[] {0x30,0xbd,0x78,0x00,0x00,0x00,0x00,0x00}; // vp9Descriptor
constexpr uint8_t vp9Subtype[] {0x00,0x10,0x00,0x00};
constexpr uint8_t vp9Rate[] {0x00,0x00,0x00,0x2d};
constexpr uint8_t vp9OutputCount[] {0x04,0x00,0x00,0x00};
constexpr uint8_t vp9Outputs[] { // x420, 420f, xf20 after the existing NV12 (5 = same flags)
 0x30,0x32,0x34,0x78,0x05,0x00,0x00,0x00, 0x66,0x30,0x32,0x34,0x05,0x00,0x00,0x00, 0x30,0x32,0x66,0x78,0x05,0x00,0x00,0x00};
constexpr uint64_t vp9DescriptorPage=vp9Descriptor&~0xfffULL, vp9DescriptorHash=0x1997b8aac85bb583ULL;
constexpr PagePatch vp9Patches[] {
 {0x0,0x887a796c0f479e7fULL,vp9Cave,sizeof(vp9Stub),vp9Stub},
 {0x14000,0xb70de16edd242bebULL,vp9Branch-0x14000,sizeof(vp9Jump),vp9Jump},
 {vp9DescriptorPage,vp9DescriptorHash,(vp9Descriptor&0xfff)+0x8,sizeof(vp9Subtype),vp9Subtype},
 {vp9DescriptorPage,vp9DescriptorHash,(vp9Descriptor&0xfff)+0x18,sizeof(vp9Rate),vp9Rate},
 {vp9DescriptorPage,vp9DescriptorHash,(vp9Descriptor&0xfff)+0x224,sizeof(vp9OutputCount),vp9OutputCount},
 {vp9DescriptorPage,vp9DescriptorHash,(vp9Descriptor&0xfff)+0x230,sizeof(vp9Outputs),vp9Outputs},
 {vp9ListPage,vp9ListHash,vp9ListSlot&0xfff,sizeof(vp9ListPointer),vp9ListPointer},
};
// A page is admitted when its whole original content has the expected hash; every piece
// for that page is then written together.
inline bool vp9Part(const void *page,uint64_t offset,bool validated,bool tainted,const char *build) {
 if(!page || !validated || tainted || !build || strcmp(build,supportedBuild))return false;
 for(const auto &part:vp9Patches)
  if(part.page==offset)return fnv1a(static_cast<const uint8_t *>(page),0x1000)==part.hash;
 return false;
}
inline void applyVP9(uint8_t *page,uint64_t offset) {
 for(const auto &part:vp9Patches)if(part.page==offset)memcpy(page+part.offset,part.bytes,part.size);
}

// Creating a counter sample buffer crashes in MTLIGCounterSampleBuffer::Init,
// and the method's error path writes through a caller's null error pointer.
// -[MTLIGAccelDevice counterSets] and -newCounterSampleBufferWithDescriptor:error:
// both return nil, so no client reaches either path.
// Every command buffer that is the queue's only active one allocates a 0x12010-byte
// posh object, and dealloc skips deleting it for such a buffer as if the queue owned it.
// The queue's pointer is set to null once and never written, so it owns none and
// WindowServer leaks 76 KB per frame. Always delete it: drop the jne after the test.
constexpr DriverSite metalSites[] {
 {0x26000,0x86d,16,
  {0x55,0x48,0x89,0xe5,0x41,0x57,0x41,0x56,0x41,0x55,0x41,0x54,0x53,0x48,0x81,0xec},
  {0x31,0xc0,0xc3,0xe5,0x41,0x57,0x41,0x56,0x41,0x55,0x41,0x54,0x53,0x48,0x81,0xec}},
 {0x26000,0xc6c,16,
  {0x55,0x48,0x89,0xe5,0x41,0x57,0x41,0x56,0x41,0x55,0x41,0x54,0x53,0x48,0x81,0xec},
  {0x31,0xc0,0xc3,0xe5,0x41,0x57,0x41,0x56,0x41,0x55,0x41,0x54,0x53,0x48,0x81,0xec}},
 {0x7e000,0xd82,16,
  {0x41,0x80,0x3c,0x06,0x00,0x75,0x0d,0xe8,0x7a,0xfa,0x01,0x00,0x49,0xc7,0x04,0x1e},
  {0x41,0x80,0x3c,0x06,0x00,0x66,0x90,0xe8,0x7a,0xfa,0x01,0x00,0x49,0xc7,0x04,0x1e}},
};
inline bool metalImage(const char *path) {
 return path && !strcmp(stripData(path),"/Library/GPUBundles/AppleIntelTGLGraphicsMTLDriver.bundle/Contents/MacOS/AppleIntelTGLGraphicsMTLDriver");
}
// A page is admitted when it holds sites and every one of them matches.
inline bool metalAdmitted(const void *page,uint64_t offset,bool validated,bool tainted,const char *build) {
 if(!page || !validated || tainted || !build || strcmp(build,supportedBuild))return false;
 bool any=false;
 for(const auto &site:metalSites) {
  if(site.page!=offset)continue;
  if(memcmp(static_cast<const uint8_t *>(page)+site.offset,site.before,site.size))return false;
  any=true;
 }
 return any;
}
inline void applyMetal(uint8_t *page,uint64_t offset) {for(const auto &site:metalSites)if(site.page==offset)applyDriver(page,site);}
}
