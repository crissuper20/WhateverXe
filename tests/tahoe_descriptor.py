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
 // Gen12 dither kernel: two parts of one slot, each gated by the hash of its original bytes.
 static_assert(sizeof(gen12Dither420v)==0xbb0,"slot size");
 assert(ditherParts[0].page+ditherParts[0].offset+ditherParts[0].size==ditherParts[1].page+ditherParts[1].offset);
 assert(ditherParts[0].page+ditherParts[0].offset==0x761f00 && ditherParts[1].source==ditherParts[0].size);
 assert(ditherParts[1].source+ditherParts[1].size==sizeof(gen12Dither420v));
 for(size_t i=2960;i<sizeof(gen12Dither420v);++i) assert(!gen12Dither420v[i]);
 {const uint8_t abc[]={'a','b','c'}; assert(fnv1a(abc,3)==0xe71fa2190541574bULL);} // Published FNV-1a 64 vector.
 if(argc>3) {
  for(auto &part:ditherParts) {
   FILE *f=fopen(argv[3],"rb"); assert(f); assert(!fseek(f,part.page,SEEK_SET)); assert(fread(page,1,sizeof(page),f)==sizeof(page)); fclose(f);
   // With -wexgen12dither a read returns the patched page from the unified buffer cache.
   if(!memcmp(page+part.offset,gen12Dither420v+part.source,part.size)) continue;
   assert(ditherPart(page,part.page,true,false,"25G332")==&part);
   assert(!ditherPart(page,part.page+0x1000,true,false,"25G332"));
   assert(!ditherPart(page,part.page,true,false,"25G241"));
   assert(!ditherPart(page,part.page,false,false,"25G332"));
   assert(!ditherPart(page,part.page,true,true,"25G332"));
   for(size_t i=0;i<part.size;i+=37) {
    uint8_t copy[sizeof(page)]; memcpy(copy,page,sizeof(page)); copy[part.offset+i]^=1;
    assert(!ditherPart(copy,part.page,true,false,"25G332"));
   }
   uint8_t before[sizeof(page)]; memcpy(before,page,sizeof(page));
   applyDither(page,part);
   assert(!memcmp(page+part.offset,gen12Dither420v+part.source,part.size));
   assert(!memcmp(page,before,part.offset));                                   // Nothing before the slot moves.
   assert(!memcmp(page+part.offset+part.size,before+part.offset+part.size,sizeof(page)-part.offset-part.size));
   assert(!ditherPart(page,part.page,true,false,"25G332"));                    // One pass only.
  }
  puts("PASS: installed video driver holds the original kernel 3 slot");
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
 // VP9 factory route: the stub fits its gap, every jump lands where the source says,
 // and each page is admitted only as the exact original page of the installed binary.
 static_assert(vp9Cave+sizeof(vp9Stub)<=vp9CaveEnd,"stub fits the header-pad gap");
 {int32_t rel; memcpy(&rel,vp9Jump+2,4); assert(vp9Jump[0]==0x0f && vp9Jump[1]==0x85 && int64_t(vp9Branch)+6+rel==int64_t(vp9Cave));}
 {int32_t rel; memcpy(&rel,vp9Stub+8,4); assert(vp9Stub[6]==0x0f && vp9Stub[7]==0x85 && int64_t(vp9Cave)+12+rel==0x149a5);}  // other subtypes
 {const uint8_t store[]={0x48,0x85,0xc0,0x74,0x0f,0x49,0x8b,0x09,0x4a,0x89,0x04,0xf9,0x45,0x31,0xe4}; // test; je fail; slot[r15]=rax; r12d=0
  assert(!memcmp(vp9Stub+0x68,store,sizeof(store)) && 0x6d+0x0f==0x7c);}
 {int32_t rel; memcpy(&rel,vp9Stub+0x78,4); assert(vp9Stub[0x77]==0xe9 && int64_t(vp9Cave)+0x7c+rel==0x149a8);}             // native success path
 {int32_t rel; memcpy(&rel,vp9Stub+0x82,4); assert(vp9Stub[0x7c]==0xbb && vp9Stub[0x7d]==1 && vp9Stub[0x81]==0xe9 && int64_t(vp9Cave)+0x86+rel==0x15072);} // ebx=1, error exit
 {int32_t rel; memcpy(&rel,vp9Stub+0x33,4); assert(vp9Stub[0x32]==0xe8 && int64_t(vp9Cave)+0x37+rel==0x23e380);}            // _dlopen stub
 {int32_t rel; memcpy(&rel,vp9Stub+0x47,4); assert(vp9Stub[0x46]==0xe8 && int64_t(vp9Cave)+0x4b+rel==0x23e386);}            // _dlsym stub
 assert(!strcmp(reinterpret_cast<const char *>(vp9Stub+0x86),"@loader_path/WEXVP9.dylib"));
 assert(!strcmp(reinterpret_cast<const char *>(vp9Stub+0x86+26),"WEXVP9Create"));
 memset(page,0,sizeof(page));
 for(auto &part:vp9Patches) assert(!vp9Part(page,part.page,true,false,"25G332")); // Any other content is refused.
 for(auto &part:vp9Patches) assert(part.offset+part.size<=0x1000);                 // Every piece stays in its page.
 if(argc>3) {
  {
   // The error exit the stub fails through: leaq -0x1b0(%rbp),%rdx; movl $0,(%rdx) (release
   // the perf capability), then free and return ebx.
   const uint8_t next[]={0x4d,0x8b,0x76,0x38,0x44,0x89,0xe6}; // 0x149a8: movq 0x38(%r14),%r14; movl %r12d,%esi
   uint8_t got[sizeof(next)]; FILE *n=fopen(argv[3],"rb"); assert(n); assert(!fseek(n,0x149a8,SEEK_SET));
   assert(fread(got,1,sizeof(got),n)==sizeof(got)); fclose(n); assert(!memcmp(got,next,sizeof(next)));
   const uint8_t exit[]={0x48,0x8d,0x95,0x50,0xfe,0xff,0xff,0xc7,0x02,0x00,0x00,0x00,0x00};
   uint8_t at[sizeof(exit)]; FILE *f=fopen(argv[3],"rb"); assert(f); assert(!fseek(f,0x15072,SEEK_SET));
   assert(fread(at,1,sizeof(at),f)==sizeof(at)); fclose(f); assert(!memcmp(at,exit,sizeof(exit)));
  }
  const uint64_t pages[]={0x0,0x14000,vp9DescriptorPage,vp9ListPage};
  for(uint64_t at:pages) {
   FILE *f=fopen(argv[3],"rb"); assert(f); assert(!fseek(f,at,SEEK_SET)); assert(fread(page,1,sizeof(page),f)==sizeof(page)); fclose(f);
   // With -wex-tgl-vp9 a read returns the patched page from the unified buffer cache.
   bool patched=true;
   for(auto &part:vp9Patches) if(part.page==at && memcmp(page+part.offset,part.bytes,part.size)) patched=false;
   if(patched) continue;
   // A page 0 still holding an earlier stub build: the gap was all zero, so zeroing the
   // cave gives back the original page, which the whole-page hash then has to confirm.
   if(at==0 && !vp9Part(page,at,true,false,"25G332")) memset(page+vp9Cave,0,vp9CaveEnd-vp9Cave);
   assert(vp9Part(page,at,true,false,"25G332"));
   assert(!vp9Part(page,at+0x1000,true,false,"25G332"));
   assert(!vp9Part(page,at,true,false,"25G241"));
   assert(!vp9Part(page,at,false,false,"25G332"));
   assert(!vp9Part(page,at,true,true,"25G332"));
   if(at==0) for(size_t i=0xc6e;i<vp9CaveEnd;++i) assert(!page[i]); // The gap is free.
   if(at==0x14000) {const uint8_t original[]={0x0f,0x85,0xbd,0x04,0x00,0x00}; assert(!memcmp(page+0x4e2,original,6));} // jne 0x149a5
   if(at==vp9ListPage) {
    // MFX list 6 is the lone 16/1 node: a NULL before and after the slot, which holds 0x78b0a0.
    uint64_t slot[3]; memcpy(slot,page+(vp9ListSlot&0xfff)-8,sizeof(slot));
    assert(!slot[0] && slot[1]==0x78b0a0 && !slot[2]);
   }
   uint8_t before[sizeof(page)]; memcpy(before,page,sizeof(page));
   applyVP9(page,at);
   size_t changed=0;
   for(size_t i=0;i<sizeof(page);++i) if(page[i]!=before[i]) {
    bool inside=false;
    for(auto &part:vp9Patches) if(part.page==at && i>=part.offset && i<part.offset+part.size) inside=true;
    assert(inside); ++changed;                                       // Nothing outside the pieces moves.
   }
   assert(changed);
   assert(!vp9Part(page,at,true,false,"25G332"));                    // One pass only.
   if(at==vp9ListPage) {uint64_t slot; memcpy(&slot,page+(vp9ListSlot&0xfff),8); assert(slot==vp9Descriptor);} // List 6 is VP9 alone.
   if(at==vp9DescriptorPage) {
    // The rewritten descriptor equals ICL's VP9 descriptor (MFX list 13), whose fields after
    // +0x18 sit 8 bytes later (ICL has a second rate field at +0x20).
    const uint8_t *tgl=page+(vp9Descriptor&0xfff);
    uint32_t sub,count; memcpy(&sub,tgl+8,4); memcpy(&count,tgl+0x224,4);
    assert(sub==0x1000 && count==4);
    if(argc>5) {
     static uint8_t icl[0x438];
     FILE *g=fopen(argv[5],"rb"); assert(g); assert(!fseek(g,0x7c41d0,SEEK_SET)); assert(fread(icl,1,sizeof(icl),g)==sizeof(icl)); fclose(g);
     assert(!memcmp(tgl,icl,0x20));                                   // type, subtype, engine, rate
     // The descriptor runs past this page: the in-page part comes from the patched page,
     // the rest (unchanged by the patch) from the file's next page.
     const size_t inPage=0x1000-(vp9Descriptor&0xfff);
     assert(!memcmp(tgl+0x20,icl+0x28,inPage-0x20));                  // input and output format lists
     static uint8_t rest[0x428];
     FILE *h=fopen(argv[3],"rb"); assert(h); assert(!fseek(h,vp9DescriptorPage+0x1000,SEEK_SET));
     assert(fread(rest,1,0x428-inPage,h)==0x428-inPage); fclose(h);
     assert(!memcmp(rest,icl+inPage+8,0x428-inPage));
     puts("PASS: rewritten TGL descriptor equals ICL's VP9 descriptor");
    }
   }
  }
  puts("PASS: installed video driver holds the original VP9 pages (skip branch, free gap, MPEG descriptor, lone 16/1 list)");
 }
 puts("PASS: descriptor gates are exact, validated-only and build-bound");
}
'''
# The VP9 stub bytes in the policy header are exactly what factory-stub.s assembles to.
import re
policy = (root/'WhateverXe/kern_tahoe_descriptor_policy.hpp').read_text()
stub = re.search(r'constexpr uint8_t vp9Stub\[\] \{(.*?)\};', policy, re.S).group(1)
assembled = subprocess.check_output(['python3', str(root/'tools/vp9/gen-stub.py'), '--bytes'], text=True).strip()
assert bytes(int(x, 16) for x in re.findall(r'0x[0-9a-f]{2}', stub)).hex() == assembled, 'regenerate vp9Stub with tools/vp9/gen-stub.py'
installed = pathlib.Path('/Library/GPUBundles/AppleIntelTGLGraphicsMTLDriver.bundle/Contents/MacOS/impostor.dylib')
with tempfile.TemporaryDirectory(prefix='tahoe-descriptor-') as temp:
    p = pathlib.Path(temp); (p/'t.cpp').write_text(harness)
    subprocess.run(['clang++','-std=c++17','-I',str(root/'WhateverXe'),str(p/'t.cpp'),'-o',str(p/'t')],check=True)
    video = pathlib.Path('/Library/GPUBundles/AppleIntelTGLGraphicsVADriver.bundle/Contents/MacOS/TGLVA')
    driver = video.with_name('AppleIntelTGLGraphicsVADriver')
    metal = installed.with_name('AppleIntelTGLGraphicsMTLDriver')
    icl = pathlib.Path('/System/Library/Extensions/AppleIntelICLGraphicsVADriver.bundle/Contents/MacOS/AppleIntelICLGraphicsVADriver')
    subprocess.run([str(p/'t')]+([str(installed),str(video),str(driver),str(metal)]+([str(icl)] if icl.exists() else []) if installed.exists() and video.exists() and driver.exists() and metal.exists() else []),check=True)
