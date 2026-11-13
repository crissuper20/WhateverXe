// Copyright (c) 2026 b00t0x. BSD-3-Clause.
#pragma once
#include <stddef.h>
#include <stdint.h>

// EXPERIMENT (-wex-cmdcap): copies of the batches the TGL kernel driver submits
// (IGAccelFIFOChannel::submitBuffer), armed and read through debug.wex_cmdcap*.
// Each batch record is followed by page records: the GPU pages its commands point at
// (batch-start targets, binding tables, surface/sampler states, pixel shader code),
// read through the submitting task's GPU page table. Read only.
namespace CommandCapture {
constexpr uint64_t magic=0x31444D4358455745,pageMagic=0x3145474158455745; // EWEXCMD1, EWEXAGE1
constexpr size_t bufferBytes=256u<<20,maxBatchBytes=1u<<20,pageBytes=4096,readBytes=32u<<20;
// streamPages: pages followed into each batch-start target (the process's own command stream).
constexpr unsigned maxPages=320,streamPages=64,bindingEntries=32;
// IOAccelCommandDescriptor fields read by submitBuffer.
constexpr size_t gpuField=0x18,cpuField=0x20,dwordsField=0x30,endField=0x68,flagA=0x69,flagB=0x6a;
struct Record {
 uint64_t magic,sequence,uptime,gpu,cpu;
 uint32_t dwords,copied,pid,flags;
 char name[32];
};
static_assert(sizeof(Record)==88,"record layout is read by cmdcap.py");
// kind: what pointed at the page. status: 0 copied, else the page-walk status (+16: copy failed).
enum Kind:uint32_t {batchStart=1,bindingTable,surfaceState,samplerState,shader};
struct PageRecord {uint64_t magic,gpu,sequence;uint32_t kind,status;};
static_assert(sizeof(PageRecord)==32,"page layout is read by cmdcap.py");
constexpr size_t recordBytes(uint32_t copied) {return sizeof(Record)+((copied+7)&~7u);}

// Dwords in the command starting with header d (Gen12 render and blitter engines).
constexpr uint32_t commandLength(uint32_t d) {
 const uint32_t type=d>>29,op=(d>>23)&0x3F;
 if(type==0)return op<0x10?1:(d&0xFF)+2;
 if(type==3 && ((d>>16)==0x6904 || (d>>16)==0x780B))return 1; // PIPELINE_SELECT, VF_STATISTICS
 if(type==2 || type==3)return (d&0xFF)+2;
 return 1;
}
struct Bases {uint64_t surface,dynamic,instruction;};
// Collects the pages the commands in words[0..count) point at. Bases carry over from
// earlier batches; STATE_BASE_ADDRESS updates them. Returns how many words the last command
// runs past count (where the next page continues), or ~0 at MI_BATCH_BUFFER_END.
template<class Add> size_t scan(const uint32_t *words,size_t count,Bases &b,Add add) {
 auto qword=[&](size_t i){return i+1<count?(uint64_t(words[i+1]&0xFFFF)<<32)|words[i]:0;};
 size_t i=0;
 for(;i<count;) {
  const uint32_t d=words[i],n=commandLength(d),h=d>>16;
  if(d==0x05000000)return ~size_t(0); // MI_BATCH_BUFFER_END
  if((d>>23)==0x31) { // MI_BATCH_BUFFER_START
   if(i+2<count) {const auto a=qword(i+1)&~3ULL;add(a,batchStart);add(a+pageBytes,batchStart);}
  } else if(h==0x6101 && i+11<count) { // STATE_BASE_ADDRESS: modify-enable bit 0 of each base
   if(words[i+4]&1)b.surface=qword(i+4)&~0xFFFULL;
   if(words[i+6]&1)b.dynamic=qword(i+6)&~0xFFFULL;
   if(words[i+10]&1)b.instruction=qword(i+10)&~0xFFFULL;
  } else if((h==0x782A || h==0x7826) && i+1<count && b.surface) { // BINDING_TABLE_POINTERS_PS/VS
   add(b.surface+(words[i+1]&0x1FFFE0),bindingTable);
  } else if((h==0x782F || h==0x782B) && i+1<count && b.dynamic) { // SAMPLER_STATE_POINTERS_PS/VS
   add(b.dynamic+(words[i+1]&~0x1FU),samplerState);
  } else if(h==0x7820 && i+2<count && b.instruction) { // 3DSTATE_PS kernel start pointer
   const auto a=b.instruction+(qword(i+1)&~0x3FULL);add(a,shader);add(a+pageBytes,shader);
  }
  i+=n?n:1;
 }
 return i-count;
}
}
