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

inline bool image(const char *path) {
 if(!path)return false;
 // vn_getpath may expose the Data mount rather than its firmlink.
 constexpr const char data[]="/System/Volumes/Data";
 if(!strncmp(path,data,sizeof(data)-1))path+=sizeof(data)-1;
 return !strcmp(path,"/Library/GPUBundles/AppleIntelTGLGraphicsMTLDriver.bundle/Contents/MacOS/impostor.dylib");
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
}
