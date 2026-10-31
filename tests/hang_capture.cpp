#include "kern_hang_capture_policy.hpp"
#include <cassert>
#include <cstdio>
#include <map>
#include <vector>
using namespace HangCapture;

namespace {
constexpr uint64_t memoryBytes=0x400000;
std::vector<uint8_t> memory(memoryBytes);
uint64_t nextTable=0x1000;
std::map<uint32_t,uint32_t> registers;
std::map<uint64_t,uint64_t> globalTable;
uint64_t globalRead(uint64_t index) {return globalTable.count(index)?globalTable[index]:0;}

bool physicalRead(uint64_t address,void *out,size_t size) {
 if(address+size>memoryBytes)return false;
 memcpy(out,memory.data()+address,size);
 return true;
}
uint64_t &entry(uint64_t table,uint64_t index) {return reinterpret_cast<uint64_t *>(memory.data()+table)[index];}
uint64_t descend(uint64_t table,uint64_t index) {
 auto &slot=entry(table,index);
 if(!slot) {nextTable+=0x1000;slot=nextTable|3;}
 return slot&addressMask;
}
void map4K(uint64_t root,uint64_t address,uint64_t physical) {
 uint64_t table=root;
 for(int shift=39;shift>12;shift-=9)table=descend(table,(address>>shift)&0x1FF);
 entry(table,(address>>12)&0x1FF)=physical|3;
}
void put(uint64_t physical,const std::vector<uint32_t> &words) {memcpy(memory.data()+physical,words.data(),words.size()*4);}
}

int main() {
 const uint64_t root=0x1000;
 const auto read=[](uint64_t a,void *o,size_t s){return physicalRead(a,o,s);};
 uint64_t physical=0;
 map4K(root,0x40001000,0x200000);
 assert(translate(read,root,0x40001234,physical) && physical==0x200234);
 assert(!translate(read,root,0x40002000,physical));         // Unmapped page.
 assert(!translate(read,0,0x40001000,physical));            // No root.
 assert(!translate(read,root,1ULL<<48,physical));           // Beyond 48 bits.

 // 2M page: PS on the directory entry.
 uint64_t directory=root;
 for(int shift=39;shift>21;shift-=9)directory=descend(directory,(0x80000000ULL>>shift)&0x1FF);
 entry(directory,0)=0x200000|0x83;
 assert(translate(read,root,0x80012345,physical) && physical==0x212345);

 // 64K table: IPS on the directory entry, entry at every sixteenth slot.
 uint64_t ips=root;
 for(int shift=39;shift>21;shift-=9)ips=descend(ips,(0xC0000000ULL>>shift)&0x1FF);
 nextTable+=0x1000;const auto table64=nextTable;
 entry(ips,0)=table64|0x803;
 entry(table64,0x10)=0x310000|3;
 assert(translate(read,root,0xC0015678,physical) && physical==0x315678);

 // Full capture: ring -> level one batch -> stuck batch -> descriptor -> kernel.
 const uint64_t ring=0x41000000,levelOne=0x42000000,batch=0x43005000,dynamic=0x44000000,code=0x45000000,surface=0x46000000;
 globalTable[ring>>12]=0x300000|1; // Deliberately absent from the context table.
 map4K(root,levelOne,0x301000);map4K(root,batch,0x302000);
 map4K(root,dynamic+0x100,0x303000);map4K(root,dynamic+0x2000,0x304000);
 map4K(root,code+0x40,0x305000);map4K(root,dynamic+0x1000,0x306000);map4K(root,surface+0x3000,0x307000);
 const uint64_t earlier=0x47000000;map4K(root,earlier,0x308000);put(0x308000,{0x11223344});
 put(0x300000,{0x18800101,uint32_t(earlier),0,0x18800101,uint32_t(levelOne|1),0,0});
 std::vector<uint32_t> state(22,0);
 state[0]=0x61010014;state[1]=0x11;state[4]=uint32_t(surface)|1;state[6]=uint32_t(dynamic)|1;state[10]=uint32_t(code)|1;
 put(0x301000,state);
 put(0x302000,{0x70020002,0,32,0x100,0x70010002,0,64,0x2000,0x7100000A,1,2,3,4});
 put(0x303100,{0x40,0,0,0x1000,0x3000,0,0,0});
 put(0x305000,{0xAABBCCDD});
 const uint64_t active=batch+8*4;
 registers={{start,uint32_t(ring)},{head,28},{tail,64},{lowerHead,uint32_t(active)},{upperHead,0},{HangCapture::batch,uint32_t(batch|1)},
  {upperBatch,0},{instruction,0x7100000A},{rootLow,uint32_t(root)},{rootHigh,0}};
 std::vector<uint8_t> out(bufferBytes);
 const auto bytes=capture([](uint32_t r){return registers.count(r)?registers[r]:0U;},globalRead,read,out.data());
 auto header=reinterpret_cast<const uint64_t *>(out.data());
 assert(header[wordMagic]==magic && header[wordRoot]==root && header[wordInstruction]==0x7100000A);
 assert(bytes==headerWords*8+header[wordPages]*recordBytes && bytes<=bufferBytes);
 assert(header[wordMatched]==1);
 assert(header[wordLevelOne]==levelOne && header[wordEarlier]==earlier);
 assert(header[wordSurface]==surface && header[wordDynamic]==dynamic && header[wordCode]==code);
 assert(header[wordDescriptorOffset]==0x100 && header[wordDescriptorBytes]==32);
 assert(header[wordCurbeOffset]==0x2000 && header[wordCurbeBytes]==64);
 assert(header[wordKernels]==1);
 bool foundKernel=false,foundSurface=false,foundSampler=false;
 for(uint64_t i=0;i<header[wordPages];++i) {
  auto record=out.data()+headerWords*8+i*recordBytes;
  uint64_t page;memcpy(&page,record,8);
  uint32_t first;memcpy(&first,record+16,4);
  if(page==code)foundKernel=first==0xAABBCCDD;
  foundSurface|=page==surface+0x3000;foundSampler|=page==dynamic+0x1000;
  for(uint64_t j=0;j<i;++j) {uint64_t other;memcpy(&other,out.data()+headerWords*8+j*recordBytes,8);assert(other!=page);} // No duplicates.
 }
 assert(foundKernel && foundSurface && foundSampler);

 // A ring missing from the global table is a recorded miss, not a context-table guess.
 registers[start]=0x48000000;
 std::vector<uint8_t> noRing(bufferBytes);
 capture([](uint32_t r){return registers.count(r)?registers[r]:0U;},globalRead,read,noRing.data());
 auto unmapped=reinterpret_cast<const uint64_t *>(noRing.data());
 assert(unmapped[wordMissed] && !unmapped[wordLevelOne]);
 registers[start]=uint32_t(ring);

 // A failed read must not leave a half-written page counted.
 auto denied=[](uint64_t a,void *o,size_t s){return s==8 && physicalRead(a,o,s);};
 std::vector<uint8_t> small(bufferBytes);
 capture([](uint32_t r){return registers.count(r)?registers[r]:0U;},globalRead,denied,small.data());
 auto partial=reinterpret_cast<const uint64_t *>(small.data());
 assert(!partial[wordPages] && partial[wordMissed]);

 // The page limit holds even when every state pointer lands on a new page.
 std::vector<uint8_t> flood(bufferBytes);
 auto all=[](uint64_t a,void *o,size_t s){memset(o,0,s);if(a<memoryBytes && a+s<=memoryBytes)memcpy(o,memory.data()+a,s);return true;};
 capture([](uint32_t r){return registers.count(r)?registers[r]:0U;},globalRead,all,flood.data());
 assert(reinterpret_cast<const uint64_t *>(flood.data())[wordPages]<=maxPages);

 assert(admitted(0x7100000A) && admitted(0x71000000));
 assert(!admitted(0x7A000004) && !admitted(0x0E009002) && !admitted(0));
 puts("PASS: hang capture walks 4K, 2M and 64K tables and follows the stuck batch");
}
