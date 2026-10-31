// Copyright (c) 2026 b00t0x. BSD-3-Clause.
#pragma once
#include <stddef.h>
#include <stdint.h>
#include <string.h>

// EXPERIMENT: read-only snapshot of a render batch stuck on MEDIA_OBJECT. It walks
// the context's page table from the engine registers, so it needs no driver layout.
namespace HangCapture {
constexpr uint64_t magic=0x31474E4148584557; // WEXHANG1
constexpr size_t headerWords=32,pageBytes=0x1000,recordBytes=16+pageBytes;
constexpr uint32_t maxPages=96,maxDescriptors=8,kernelPages=4,windowBefore=4,windowAfter=2,levelOnePages=8;
constexpr size_t bufferBytes=headerWords*8+maxPages*recordBytes;
constexpr uint64_t addressMask=0x0000FFFFFFFFF000ULL;
enum Register:uint32_t {tail=0x2030,head=0x2034,start=0x2038,upperHead=0x205C,instruction=0x2068,lowerHead=0x2074,batch=0x2140,upperBatch=0x2168,rootLow=0x2270,rootHigh=0x2274};
enum Word {wordMagic,wordRoot,wordActiveHead,wordBatch,wordInstruction,wordRingStart,wordRingHead,wordRingTail,wordPages,wordMissed,wordMatched,
 wordLevelOne,wordGeneral,wordSurface,wordDynamic,wordCode,wordDescriptorOffset,wordDescriptorBytes,wordCurbeOffset,wordCurbeBytes,wordKernels,wordEarlier};

constexpr bool admitted(uint32_t instruction) {return instruction>>16==0x7100;} // MEDIA_OBJECT

// PS ends the walk at 1G or 2M. A 64K table keeps its entry on every sixteenth slot.
template<class Physical> bool translate(Physical read,uint64_t root,uint64_t address,uint64_t &physical) {
 uint64_t table=root&addressMask,entry=0;
 if(!table || address>>48)return false;
 for(int shift=39;shift>12;shift-=9) {
  if(!read(table+((address>>shift)&0x1FF)*8,&entry,sizeof(entry)) || !(entry&1))return false;
  if(shift<39 && (entry&0x80)) {
   const uint64_t mask=(1ULL<<shift)-1;
   physical=(entry&addressMask&~mask)|(address&mask);
   return true;
  }
  if(shift==21 && (entry&0x800)) {
   table=entry&addressMask;
   if(!read(table+((address>>12)&0x1F0)*8,&entry,sizeof(entry)) || !(entry&1))return false;
   physical=(entry&addressMask&~0xFFFFULL)|(address&0xFFFF);
   return true;
  }
  table=entry&addressMask;
 }
 if(!read(table+((address>>12)&0x1FF)*8,&entry,sizeof(entry)) || !(entry&1))return false;
 physical=(entry&addressMask)|(address&0xFFF);
 return true;
}

inline uint64_t joined(const uint32_t *words,size_t index) {return (uint64_t(words[index+1]&0xFFFF)<<32)|(words[index]&~0xFFFU);}

// Keeps the last state command in each page, stopping at limit dwords.
inline void scan(const uint32_t *words,size_t limit,uint64_t *header) {
 for(size_t i=0;i<limit;++i) {
  const auto command=words[i]>>16;
  if(command==0x6101 && i+11<pageBytes/4) {
   header[wordGeneral]=joined(words,i+1);header[wordSurface]=joined(words,i+4);
   header[wordDynamic]=joined(words,i+6);header[wordCode]=joined(words,i+10);
  } else if(command==0x7002 && i+3<pageBytes/4) {
   header[wordDescriptorBytes]=words[i+2];header[wordDescriptorOffset]=words[i+3];
  } else if(command==0x7001 && i+3<pageBytes/4) {
   header[wordCurbeBytes]=words[i+2];header[wordCurbeOffset]=words[i+3];
  }
 }
}

// The ring is mapped by the global table, every batch by the context table.
template<class Register,class Global,class Physical> size_t capture(Register reg,Global global,Physical read,uint8_t *out) {
 auto header=reinterpret_cast<uint64_t *>(out);
 memset(header,0,headerWords*8);
 header[wordMagic]=magic;
 const uint64_t root=(uint64_t(reg(rootHigh))<<32)|reg(rootLow);
 const uint64_t active=(uint64_t(reg(upperHead))<<32)|reg(lowerHead);
 header[wordRoot]=root;header[wordActiveHead]=active;
 header[wordBatch]=(uint64_t(reg(upperBatch))<<32)|reg(batch);
 header[wordInstruction]=reg(instruction);header[wordRingStart]=reg(start);
 header[wordRingHead]=reg(head);header[wordRingTail]=reg(tail);
 auto records=out+headerWords*8;
 auto add=[&](uint64_t address,bool isGlobal=false) {
  const auto page=address&~uint64_t(pageBytes-1);
  for(uint64_t i=0;i<header[wordPages];++i)if(!memcmp(records+i*recordBytes,&page,sizeof(page)))return true;
  uint64_t physical=0;
  auto record=records+header[wordPages]*recordBytes;
  const auto entry=isGlobal?global(page>>12):0;
  if(isGlobal)physical=entry&addressMask;
  if(header[wordPages]>=maxPages || (isGlobal?!(entry&1):!translate(read,root,page,physical)) || !read(physical,record+16,pageBytes)) {++header[wordMissed];return false;}
  memcpy(record,&page,sizeof(page));memcpy(record+8,&physical,sizeof(physical));
  ++header[wordPages];
  return true;
 };
 // The ring's batch starts are older than the batch they chained to, so scan them first.
 const uint64_t ringHead=header[wordRingStart]+(header[wordRingHead]&0x1FFFFC);
 if(add(ringHead,true)) {
  auto ring=reinterpret_cast<const uint32_t *>(records+(header[wordPages]-1)*recordBytes+16);
  for(size_t i=0;i+2<=(ringHead&(pageBytes-1))/4;++i)if(ring[i]>>16==0x1880) {
   header[wordEarlier]=header[wordLevelOne];
   header[wordLevelOne]=(uint64_t(ring[i+2]&0xFFFF)<<32)|(ring[i+1]&~3U);
  }
 }
 const Word levels[] {wordEarlier,wordLevelOne};
 for(const auto level:levels)if(header[level])for(uint32_t i=0;i<levelOnePages;++i)add(header[level]+i*pageBytes);
 const auto activePage=active&~uint64_t(pageBytes-1);
 for(uint32_t i=windowBefore;i;--i)if(activePage>=i*pageBytes)add(activePage-i*pageBytes);
 for(uint32_t i=0;i<=windowAfter;++i)add(activePage+i*pageBytes);
 for(uint64_t i=0;i<header[wordPages];++i) {
  uint64_t page;memcpy(&page,records+i*recordBytes,sizeof(page));
  auto words=reinterpret_cast<const uint32_t *>(records+i*recordBytes+16);
  const bool last=page==activePage;
  scan(words,last?(active&(pageBytes-1))/4:pageBytes/4,header);
  if(last) {
   const size_t at=(active&(pageBytes-1))/4;
   for(size_t back=0;back<=4 && back<=at;++back)if(words[at-back]==header[wordInstruction])header[wordMatched]=1;
  }
 }
 const auto descriptors=header[wordDynamic]+header[wordDescriptorOffset];
 if(!header[wordDynamic] || !header[wordDescriptorBytes])return headerWords*8+header[wordPages]*recordBytes;
 add(descriptors);
 if(header[wordCurbeBytes])add(header[wordDynamic]+header[wordCurbeOffset]);
 auto count=header[wordDescriptorBytes]/32;
 if(count>maxDescriptors)count=maxDescriptors;
 for(uint64_t i=0;i<count;++i) {
  uint32_t descriptor[8];uint64_t physical;
  if(!translate(read,root,descriptors+i*32,physical) || !read(physical,descriptor,sizeof(descriptor))) {++header[wordMissed];continue;}
  const auto kernel=header[wordCode]+((uint64_t(descriptor[1]&0xFFFF)<<32)|(descriptor[0]&~0x3FU));
  ++header[wordKernels];
  for(uint32_t page=0;page<kernelPages;++page)add(kernel+page*pageBytes);
  if(descriptor[3]&~0x1FU)add(header[wordDynamic]+(descriptor[3]&~0x1FU));
  if(descriptor[4]&~0x1FU)add(header[wordSurface]+(descriptor[4]&~0x1FU));
 }
 return headerWords*8+header[wordPages]*recordBytes;
}
}
