#!/usr/bin/env python3
"""Run the Tahoe descriptor gate decision against a synthetic first page.

With the installed graphics payload present, also require the real image to
satisfy both gates, so a package update cannot silently leave them stale.
"""
import pathlib, subprocess, tempfile
root = pathlib.Path(__file__).resolve().parents[1]
harness = r'''
#include "kern_tahoe_descriptor_policy.hpp"
#include <cassert>
#include <cstdio>
using namespace TahoeDescriptor;
static uint8_t page[4096];
static void fresh() { memset(page,0x90,sizeof(page)); for(auto &g:gates) memcpy(page+g.offset,g.code,sizeof(g.code)); }
int main(int argc,char **argv) {
 fresh();
 assert(admitted(page,0,true,false,"25G332"));
 assert(!admitted(page,0,true,false,"25G241")); // The native gate already passes there.
 assert(!admitted(page,0,true,false,""));       // launchd has not published the build.
 assert(!admitted(page,0,true,false,nullptr));
 assert(!admitted(page,0x1000,true,false,"25G332"));
 assert(!admitted(page,0,false,false,"25G332")); // Never touch unverified bytes.
 assert(!admitted(page,0,true,true,"25G332"));
 assert(!admitted(nullptr,0,true,false,"25G332"));
 for(auto &g:gates) for(size_t i=0;i<sizeof(g.code);++i) {
  fresh(); page[g.offset+i]^=0xff;
  assert(!admitted(page,0,true,false,"25G332"));
 }
 fresh(); apply(page);
 assert(!admitted(page,0,true,false,"25G332")); // Idempotent: a second pass finds nothing.
 for(auto &g:gates) {
  // The comparisons read the build at +0 and +3; both must equal the real one.
  assert(!memcmp(page+g.offset+1,"25G3",4));
  assert(!memcmp(page+g.offset+9,"332",4));
  assert(page[g.offset+5]==0x33 && page[g.offset+13]==0x33 && page[g.offset+18]==0x75);
 }
 assert(image("/Library/GPUBundles/AppleIntelTGLGraphicsMTLDriver.bundle/Contents/MacOS/impostor.dylib"));
 assert(image("/System/Volumes/Data/Library/GPUBundles/AppleIntelTGLGraphicsMTLDriver.bundle/Contents/MacOS/impostor.dylib"));
 assert(!image("/tmp/Library/GPUBundles/AppleIntelTGLGraphicsMTLDriver.bundle/Contents/MacOS/impostor.dylib"));
 assert(!image("/Library/GPUBundles/AppleIntelTGLGraphicsMTLDriver.bundle/Contents/MacOS/impostor.dylib.bak"));
 assert(!image(nullptr));
 if(argc>1) {
  FILE *f=fopen(argv[1],"rb"); assert(f); assert(fread(page,1,sizeof(page),f)==sizeof(page)); fclose(f);
  assert(admitted(page,0,true,false,"25G332"));
  puts("PASS: installed impostor.dylib satisfies both gates");
 }
 puts("PASS: descriptor gates are exact, validated-only and build-bound");
}
'''
installed = pathlib.Path('/Library/GPUBundles/AppleIntelTGLGraphicsMTLDriver.bundle/Contents/MacOS/impostor.dylib')
with tempfile.TemporaryDirectory(prefix='tahoe-descriptor-') as temp:
    p = pathlib.Path(temp); (p/'t.cpp').write_text(harness)
    subprocess.run(['clang++','-std=c++17','-I',str(root/'WhateverXe'),str(p/'t.cpp'),'-o',str(p/'t')],check=True)
    subprocess.run([str(p/'t')]+([str(installed)] if installed.exists() else []),check=True)
