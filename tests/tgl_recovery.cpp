#include "../WhateverXe/kern_tgl_recovery.hpp"
#include <cassert>
#include <cstdio>
#include <cstring>
#include <initializer_list>

namespace {
alignas(16) uint8_t channel[0x180],affected[0x180],ring[0x100],context[0xD0];
alignas(16) uint8_t owner[0x1300],scheduler[0x200],otherScheduler[0x200];
alignas(16) uint8_t ringVT[0x200],schedulerVT[0x200],mmio[0x20000];
unsigned resets,resumes,stage;bool nativeOK,replaceScheduler;
bool reset(void *r,void *c) {
	assert(r==ring && c==context && stage++==0);++resets;
	// Native side effects must survive. No caller-synthesized completion.
	TGLRecovery::field<uint32_t>(affected,0x178)=0xABCDEF;
	if (replaceScheduler) TGLRecovery::field<void *>(owner,0x1250)=otherScheduler;
	return nativeOK;
}
void resume(void *s) {
	assert(s==(replaceScheduler ? otherScheduler : scheduler) && stage++==1);++resumes;
}
}
int main() {
	for (bool ok:{false,true}) for (bool replace:{false,true}) for (unsigned initial:{0U,5U,0xFFFFFFFFU}) {
		memset(channel,0,sizeof(channel));memset(affected,0,sizeof(affected));
		TGLRecovery::field<void *>(channel,0x130)=ring;
		TGLRecovery::field<void *>(channel,0x18)=owner;
		TGLRecovery::field<void *>(ring,0)=ringVT;
		TGLRecovery::field<void *>(ring,0x20)=context;
		TGLRecovery::field<void *>(context,0xB8)=affected;
		TGLRecovery::field<void *>(owner,0x1250)=scheduler;
		TGLRecovery::field<void *>(scheduler,0)=schedulerVT;
		TGLRecovery::field<void *>(otherScheduler,0)=schedulerVT;
		TGLRecovery::field<decltype(&reset)>(ringVT,0x168)=reset;
		TGLRecovery::field<decltype(&resume)>(schedulerVT,0x180)=resume;
		TGLRecovery::field<uint32_t>(affected,0x20)=2;
		TGLRecovery::field<uint32_t>(affected,0x17C)=initial;
		nativeOK=ok;replaceScheduler=replace;resets=resumes=stage=0;
		const auto result=TGLRecovery::resetAndResume(channel);
		assert(resets==1 && resumes==1 && stage==2 && result.resetOK==ok);
		assert(result.affected==reinterpret_cast<uintptr_t>(affected) && result.index==2);
		assert(result.failuresBefore==initial && result.failuresAfter==initial+unsigned(!ok));
		assert(TGLRecovery::field<uint32_t>(affected,0x178)==0xABCDEF);
		// Affected channel comes from the context; do not update caller blindly.
		assert(TGLRecovery::field<uint32_t>(channel,0x17C)==0);
	}
	for (uint32_t hung:{0U,1U}) {
		memset(mmio,0,sizeof(mmio));
		using namespace TGLRecovery;
		for (const auto &r:rcsRegisters) field<uint32_t>(mmio,r.reg)=r.reg^0x55;
		for (const auto &r:ccsRegisters) field<uint32_t>(mmio,r.reg)=r.reg^0x55;
		for (const auto &r:sharedRegisters) field<uint32_t>(mmio,r.reg)=r.reg^0x55;
		field<uint32_t>(mmio,rcuMode)=1;
		Snapshot snapshot {};
		save(mmio,snapshot);
		assert(snapshot.ready && snapshot.shared[0]==1);
		memset(mmio,0,sizeof(mmio)); // The reset clears both engines.
		restoreSibling(mmio,hung,snapshot);
		assert(!snapshot.ready && snapshot.rcuAfterReset==0);
		assert(field<uint32_t>(mmio,rcuMode)==0xFFFF0001 && snapshot.rcuRestored==0xFFFF0001);
		assert(field<uint32_t>(mmio,0x1A4D0)==(0x1A4D0^0x55));
		assert(field<uint32_t>(mmio,0xB09C)==(0xB09C^0x55) && field<uint32_t>(mmio,0xE434)==(0xE434^0x55));
		// Both engines' idle count and error mask come back whichever engine hung.
		for (uint32_t reg:{0x2054U,0x20B4U,0x1A054U,0x1A0B4U}) assert(field<uint32_t>(mmio,reg)==(reg^0x55));
		// The native reset owns the hung engine's list.
		const auto &sibling=hung==0 ? ccsRegisters[0] : rcsRegisters[0];
		const auto &own=hung==0 ? rcsRegisters[0] : ccsRegisters[0];
		assert(field<uint32_t>(mmio,sibling.reg)==(sibling.reg^0x55));
		assert(field<uint32_t>(mmio,own.reg)==0);
		const auto &masked=hung==0 ? ccsRegisters[1] : rcsRegisters[2];
		assert(field<uint32_t>(mmio,masked.reg)==((masked.reg^0x55)|0xFFFF0000U));
	}
	puts("14 recovery cases passed: native result, count, order, affected channel, owner reload, sibling restore");
}
