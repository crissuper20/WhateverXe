// Exact TGL donor layout, with the 20G1443 ICL recovery caller contract.
// The caller must qualify the binary and select host scheduler 5 first.
#ifndef kern_tgl_recovery_hpp
#define kern_tgl_recovery_hpp
#include <stdint.h>

namespace TGLRecovery {
template<typename T> inline T &field(void *p, unsigned offset) {
	return *reinterpret_cast<T *>(static_cast<uint8_t *>(p)+offset);
}

// RCS and CCS share reset domain 2, so resetting either clears both, but the
// native reset restores and replays only the hung engine. Without this CCS
// stays off and its channels never complete. Register lists come from the
// donor's rcsRegisters and ccsRegisters. Shared registers are reprogrammed
// natively only at boot and wake, so they are also restored here.
struct Register {
	uint32_t reg;
	bool masked;
};
constexpr Register rcsRegisters[] {
	{0x2080,false},{0x2134,false},{0x20C0,true},{0x7000,true},{0x7004,true},{0x20A8,false},{0x209C,true},{0x2090,true},
	{0x4090,false},{0x229C,true},{0x20A0,false},{0x20E4,true},{0x9430,false},{0x7010,true},{0xD08,false},{0xE194,true},
	{0xB004,false},{0x20EC,true},{0x2580,true},{0x2058,false},{0x20E0,true},{0x20D4,true},{0x24D0,false},{0x24D4,false},
	{0x24D8,false},{0x24DC,false},{0x24E0,false},{0x24EC,false},{0x24F0,false},{0x24F4,false},{0x24F8,false},{0x24FC,false}};
constexpr Register ccsRegisters[] {{0x1A080,false},{0x1A0C0,true},{0x1A09C,true},{0x1A29C,true}};
constexpr uint32_t rcuMode=0x14800;
// The reset also clears the L3 cache policy table (LNCFCMOCS 0xB020-0xB09C) and
// 0xB104, 0xB170, 0xE434; seen on 25G332, and leaving them cost 4-15x speed.
// 0xB170 bit 31 and 0xE434 are live state and do not keep the restored value.
// EXPERIMENT: the reset also sets both engines' power-context idle count
// (0x2054/0x1A054, 0xa to 0x40) and error mask (0x20B4/0x1A0B4, fffffffa to
// ffffffff), which neither engine's native list restores. Idea credit:
// retropineaple/WhateverXe (adlp-edp), which restores the RCS pair.
constexpr Register sharedRegisters[] {{rcuMode,true},{0xCE90,true},{0x1A4D0,false},{0x1A0A8,false},{0x1A098,false},
	{0x2054,false},{0x20B4,false},{0x1A054,false},{0x1A0B4,false},
	{0xB020,false},{0xB024,false},{0xB028,false},{0xB02C,false},{0xB030,false},{0xB034,false},{0xB038,false},{0xB03C,false},
	{0xB040,false},{0xB044,false},{0xB048,false},{0xB04C,false},{0xB050,false},{0xB054,false},{0xB058,false},{0xB05C,false},
	{0xB060,false},{0xB064,false},{0xB068,false},{0xB06C,false},{0xB070,false},{0xB074,false},{0xB078,false},{0xB07C,false},
	{0xB080,false},{0xB084,false},{0xB088,false},{0xB08C,false},{0xB090,false},{0xB094,false},{0xB098,false},{0xB09C,false},
	{0xB104,false},{0xB170,false},{0xE434,false}};
constexpr unsigned rcsCount=sizeof(rcsRegisters)/sizeof(rcsRegisters[0]);
constexpr unsigned ccsCount=sizeof(ccsRegisters)/sizeof(ccsRegisters[0]);
constexpr unsigned sharedCount=sizeof(sharedRegisters)/sizeof(sharedRegisters[0]);

struct Snapshot {
	uint32_t rcs[rcsCount],ccs[ccsCount],shared[sharedCount];
	uint32_t rcuAfterReset,rcuRestored;
	bool ready;
};

inline uint32_t read(uint8_t *mmio, uint32_t reg) {
	return *reinterpret_cast<volatile uint32_t *>(mmio+reg);
}
inline void write(uint8_t *mmio, const Register &r, uint32_t value) {
	*reinterpret_cast<volatile uint32_t *>(mmio+r.reg)=r.masked ? value|0xFFFF0000U : value;
}

// Forcewake must be held.
inline void save(uint8_t *mmio, Snapshot &s) {
	for (unsigned i=0;i<rcsCount;++i) s.rcs[i]=read(mmio,rcsRegisters[i].reg);
	for (unsigned i=0;i<ccsCount;++i) s.ccs[i]=read(mmio,ccsRegisters[i].reg);
	for (unsigned i=0;i<sharedCount;++i) s.shared[i]=read(mmio,sharedRegisters[i].reg);
	s.ready=true;
}

// After the reset, before any replay. The native code restored the hung engine,
// so this writes the shared registers and the other engine's list.
inline void restoreSibling(uint8_t *mmio, uint32_t hung, Snapshot &s) {
	s.rcuAfterReset=read(mmio,rcuMode);
	for (unsigned i=0;i<sharedCount;++i) write(mmio,sharedRegisters[i],s.shared[i]);
	if (hung==0) for (unsigned i=0;i<ccsCount;++i) write(mmio,ccsRegisters[i],s.ccs[i]);
	else for (unsigned i=0;i<rcsCount;++i) write(mmio,rcsRegisters[i],s.rcs[i]);
	s.rcuRestored=read(mmio,rcuMode);
	s.ready=false;
}

struct Result {
	uintptr_t ring, context, affected;
	uint32_t index, failuresBefore, failuresAfter;
	bool resetOK;
};

// ICL 20G1443 resetHardwareAndReplay (4A712): reset once, account a native
// failure, resume scheduling, return to IOAccel's error/event processing.
// TGL's lower reset still owns hardware reset, context replay and CSB handling.
// Do not append a new stamp or wait inside this recovery work-loop callback.
inline Result resetAndResume(void *channel) {
	void *ring=field<void *>(channel,0x130);
	void *context=field<void *>(ring,0x20);
	void *affected=field<void *>(context,0xB8); // ICL uses B0, NOT compatible.
	Result result {reinterpret_cast<uintptr_t>(ring),reinterpret_cast<uintptr_t>(context),
		reinterpret_cast<uintptr_t>(affected),field<uint32_t>(affected,0x20),
		field<uint32_t>(affected,0x17C),0,false};
	using Reset=bool (*)(void *,void *);
	result.resetOK=field<Reset>(field<void *>(ring,0),0x168)(ring,context);
	if (!result.resetOK) ++field<uint32_t>(affected,0x17C);
	result.failuresAfter=field<uint32_t>(affected,0x17C);
	// Reload after reset, as the native ICL caller does.
	void *owner=field<void *>(channel,0x18);
	void *scheduler=field<void *>(owner,0x1250); // ICL uses1280.
	using Resume=void (*)(void *);
	field<Resume>(field<void *>(scheduler,0),0x180)(scheduler);
	return result;
}
}
#endif
