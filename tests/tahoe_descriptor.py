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
  // Under the hook a read returns the patched page from the unified buffer cache.
  uint8_t expected[sizeof(page)]; memcpy(expected,page,sizeof(page));
  for(auto &g:gates) memcpy(expected+g.offset,g.code,sizeof(g.code));
  apply(expected);
  assert(admitted(page,0,true,false,"25G332") || !memcmp(page,expected,sizeof(page)));
  puts("PASS: installed impostor.dylib satisfies both gates");
 }
 // TGLVA build literal, on its own page and never confused with the bridge.
 memset(page,0x90,sizeof(page)); memcpy(page+videoOffset,videoCode,sizeof(videoCode));
 assert(videoAdmitted(page,videoPage,true,false,"25G332"));
 assert(!videoAdmitted(page,0,true,false,"25G332"));
 assert(!videoAdmitted(page,videoPage,true,false,"25G241"));
 assert(!videoAdmitted(page,videoPage,false,false,"25G332"));
 assert(!videoAdmitted(page,videoPage,true,true,"25G332"));
 assert(!videoAdmitted(nullptr,videoPage,true,false,"25G332"));
 for(size_t i=0;i<sizeof(videoCode);++i) {
  memcpy(page+videoOffset,videoCode,sizeof(videoCode)); page[videoOffset+i]^=0xff;
  assert(!videoAdmitted(page,videoPage,true,false,"25G332"));
 }
 memcpy(page+videoOffset,videoCode,sizeof(videoCode)); applyVideo(page);
 assert(!memcmp(page+videoOffset+videoBuild,"25G332",7));
 assert(!memcmp(page+videoOffset,videoCode,videoBuild));
 assert(!memcmp(page+videoOffset+videoBuild+7,videoCode+videoBuild+7,sizeof(videoCode)-videoBuild-7));
 assert(!videoAdmitted(page,videoPage,true,false,"25G332"));
 assert(videoImage("/System/Volumes/Data/Library/GPUBundles/AppleIntelTGLGraphicsVADriver.bundle/Contents/MacOS/TGLVA"));
 assert(!videoImage("/Library/GPUBundles/AppleIntelTGLGraphicsMTLDriver.bundle/Contents/MacOS/impostor.dylib"));
 assert(!image("/Library/GPUBundles/AppleIntelTGLGraphicsVADriver.bundle/Contents/MacOS/TGLVA"));
 assert(!videoImage(nullptr));
 if(argc>2) {
  FILE *f=fopen(argv[2],"rb"); assert(f); assert(!fseek(f,videoPage,SEEK_SET)); assert(fread(page,1,sizeof(page),f)==sizeof(page)); fclose(f);
  assert(videoAdmitted(page,videoPage,true,false,"25G332") || !memcmp(page+videoOffset+videoBuild,"25G332",7));
  puts("PASS: installed TGLVA satisfies the video gate");
 }
 // Pixel-transfer sites: each page alone, exact bytes, one pass only, same sizes.
 for(auto &site:driverSites) {
  assert(site.size<=sizeof(site.before));
  memset(page,0x90,sizeof(page)); memcpy(page+site.offset,site.before,site.size);
  assert(driverSite(page,site.page,true,false,"25G332")==&site);
  assert(!driverSite(page,site.page+0x1000,true,false,"25G332"));
  assert(!driverSite(page,site.page,true,false,"25G241"));
  assert(!driverSite(page,site.page,false,false,"25G332"));
  assert(!driverSite(page,site.page,true,true,"25G332"));
  for(size_t i=0;i<site.size;++i) {
   memcpy(page+site.offset,site.before,site.size); page[site.offset+i]^=0xff;
   assert(!driverSite(page,site.page,true,false,"25G332"));
  }
  memcpy(page+site.offset,site.before,site.size); applyDriver(page,site);
  assert(!memcmp(page+site.offset,site.after,site.size));
  assert(!driverSite(page,site.page,true,false,"25G332"));
 }
 // The rewritten block stores slot 2, then jumps to the failure path at 0x1b1d5f.
 {auto &a=driverSites[0];assert(a.after[7]==0xe9 && 0x1b1d40+12+a.after[8]==0x1b1d5f && !a.after[9] && !a.after[10] && !a.after[11] && a.size==21);
  for(size_t i=12;i<a.size;++i)assert(a.after[i]==0x90);}
 assert(driverImage("/System/Volumes/Data/Library/GPUBundles/AppleIntelTGLGraphicsVADriver.bundle/Contents/MacOS/AppleIntelTGLGraphicsVADriver"));
 assert(!driverImage("/Library/GPUBundles/AppleIntelTGLGraphicsVADriver.bundle/Contents/MacOS/TGLVA"));
 assert(!driverImage(nullptr));
 if(argc>3) {
  for(auto &site:driverSites) {
   FILE *f=fopen(argv[3],"rb"); assert(f); assert(!fseek(f,site.page,SEEK_SET)); assert(fread(page,1,sizeof(page),f)==sizeof(page)); fclose(f);
   // A running system may still hold the earlier build's pages until it reboots.
   const uint8_t earlier[]={0x48,0x89,0x81,0x20,0x09,0x00,0x00,0x48,0x89,0x81,0x10,0x09,0x00,0x00,0x48,0x85,0xc0,0x74,0x0c,0x90,0x90};
   assert(driverSite(page,site.page,true,false,"25G332")==&site || !memcmp(page+site.offset,site.after,site.size) || (site.page==0x1b1000 && !memcmp(page+site.offset,earlier,sizeof(earlier))));
  }
  puts("PASS: installed video driver satisfies both pixel-transfer sites");
 }
 // Metal driver sites: each page is admitted only with all of its own sites, the others are ignored.
 const uint64_t metalPages[]={0x26000,0x7e000};
 for(uint64_t metalPage:metalPages) {
  auto freshMetal=[&]{memset(page,0x90,sizeof(page)); for(auto &s:metalSites) if(s.page==metalPage) memcpy(page+s.offset,s.before,s.size);};
  freshMetal();
  assert(metalAdmitted(page,metalPage,true,false,"25G332"));
  assert(!metalAdmitted(page,metalPage+0x1000,true,false,"25G332"));
  assert(!metalAdmitted(page,metalPage,true,false,"25G241"));
  assert(!metalAdmitted(page,metalPage,false,false,"25G332"));
  assert(!metalAdmitted(page,metalPage,true,true,"25G332"));
  assert(!metalAdmitted(nullptr,metalPage,true,false,"25G332"));
  for(auto &s:metalSites) if(s.page==metalPage) for(size_t i=0;i<s.size;++i) {
   freshMetal(); page[s.offset+i]^=0xff;
   assert(!metalAdmitted(page,metalPage,true,false,"25G332"));
  }
  freshMetal(); applyMetal(page,metalPage);
  for(auto &s:metalSites) if(s.page==metalPage) assert(!memcmp(page+s.offset,s.after,s.size));
  assert(!metalAdmitted(page,metalPage,true,false,"25G332"));
 }
 // The counter sites return nil at entry; the posh site only drops the jne that skips the delete.
 for(auto &s:metalSites) if(s.page==0x26000) assert(s.after[0]==0x31 && s.after[1]==0xc0 && s.after[2]==0xc3);
 for(auto &s:metalSites) if(s.page==0x7e000) {
  for(size_t i=0;i<s.size;++i) if(i!=5 && i!=6) assert(s.before[i]==s.after[i]);
  assert(s.before[5]==0x75 && s.after[5]==0x66 && s.after[6]==0x90);
 }
 assert(!metalAdmitted(page,0x30000,true,false,"25G332"));
 assert(metalImage("/System/Volumes/Data/Library/GPUBundles/AppleIntelTGLGraphicsMTLDriver.bundle/Contents/MacOS/AppleIntelTGLGraphicsMTLDriver"));
 assert(!metalImage("/Library/GPUBundles/AppleIntelTGLGraphicsMTLDriver.bundle/Contents/MacOS/impostor.dylib"));
 assert(!metalImage(nullptr));
 if(argc>4) {
  for(uint64_t metalPage:metalPages) {
   FILE *f=fopen(argv[4],"rb"); assert(f); assert(!fseek(f,metalPage,SEEK_SET)); assert(fread(page,1,sizeof(page),f)==sizeof(page)); fclose(f);
   for(auto &s:metalSites) if(s.page==metalPage) assert(!memcmp(page+s.offset,s.before,s.size) || !memcmp(page+s.offset,s.after,s.size));
  }
  puts("PASS: installed Metal driver satisfies the counter and posh sites");
 }
 puts("PASS: descriptor gates are exact, validated-only and build-bound");
}
'''
installed = pathlib.Path('/Library/GPUBundles/AppleIntelTGLGraphicsMTLDriver.bundle/Contents/MacOS/impostor.dylib')
with tempfile.TemporaryDirectory(prefix='tahoe-descriptor-') as temp:
    p = pathlib.Path(temp); (p/'t.cpp').write_text(harness)
    subprocess.run(['clang++','-std=c++17','-I',str(root/'WhateverXe'),str(p/'t.cpp'),'-o',str(p/'t')],check=True)
    video = pathlib.Path('/Library/GPUBundles/AppleIntelTGLGraphicsVADriver.bundle/Contents/MacOS/TGLVA')
    driver = video.with_name('AppleIntelTGLGraphicsVADriver')
    metal = installed.with_name('AppleIntelTGLGraphicsMTLDriver')
    subprocess.run([str(p/'t')]+([str(installed),str(video),str(driver),str(metal)] if installed.exists() and video.exists() and driver.exists() and metal.exists() else []),check=True)
