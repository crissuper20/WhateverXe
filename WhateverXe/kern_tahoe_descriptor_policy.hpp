// Copyright (c) 2026 b00t0x. BSD-3-Clause.
#pragma once
#include <stddef.h>
#include <stdint.h>
#include <string.h>

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

// Creating a counter sample buffer crashes in MTLIGCounterSampleBuffer::Init,
// and the method's error path writes through a caller's null error pointer.
// -[MTLIGAccelDevice counterSets] and -newCounterSampleBufferWithDescriptor:error:
// both return nil, so no client reaches either path.
constexpr DriverSite metalSites[] {
 {0x26000,0x86d,16,
  {0x55,0x48,0x89,0xe5,0x41,0x57,0x41,0x56,0x41,0x55,0x41,0x54,0x53,0x48,0x81,0xec},
  {0x31,0xc0,0xc3,0xe5,0x41,0x57,0x41,0x56,0x41,0x55,0x41,0x54,0x53,0x48,0x81,0xec}},
 {0x26000,0xc6c,16,
  {0x55,0x48,0x89,0xe5,0x41,0x57,0x41,0x56,0x41,0x55,0x41,0x54,0x53,0x48,0x81,0xec},
  {0x31,0xc0,0xc3,0xe5,0x41,0x57,0x41,0x56,0x41,0x55,0x41,0x54,0x53,0x48,0x81,0xec}},
};
inline bool metalImage(const char *path) {
 return path && !strcmp(stripData(path),"/Library/GPUBundles/AppleIntelTGLGraphicsMTLDriver.bundle/Contents/MacOS/AppleIntelTGLGraphicsMTLDriver");
}
inline bool metalAdmitted(const void *page,uint64_t offset,bool validated,bool tainted,const char *build) {
 if(offset!=metalSites[0].page || !page || !validated || tainted || !build || strcmp(build,supportedBuild))return false;
 for(const auto &site:metalSites)
  if(memcmp(static_cast<const uint8_t *>(page)+site.offset,site.before,site.size))return false;
 return true;
}
inline void applyMetal(uint8_t *page) {for(const auto &site:metalSites)applyDriver(page,site);}
}
