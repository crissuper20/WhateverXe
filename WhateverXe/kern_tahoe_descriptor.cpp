// Copyright (c) 2026 b00t0x. BSD-3-Clause.
#include "kern_tahoe_descriptor.hpp"
#include "kern_tahoe_descriptor_policy.hpp"
#include <Headers/kern_api.hpp>
#include <Headers/kern_mach.hpp>
#include <IOKit/IORegistryEntry.h>

namespace {
using Validate=void (*)(void *,void *,uint64_t,const void *,int *,int *,int *);
Validate originalValidate;
int (*getPath)(void *,char *,int *);
const char *runningBuild;

// Keeps the path buffer off the stack of every other page validation.
__attribute__((noinline)) bool pathMatches(void *vnode,bool (*match)(const char *)) {
 char path[1024];
 int length=sizeof(path);
 // vn_getpath does not enter the filesystem, and only a matching page reaches it.
 return !getPath(vnode,path,&length) && match(path);
}

// Native rdi..r9 plus nx at 0x10(%rbp): validated is written only after the hash.
void validatePage(void *vnode,void *pager,uint64_t offset,const void *data,int *validated,int *tainted,int *nx) {
 originalValidate(vnode,pager,offset,data,validated,tainted,nx);
 if(!vnode)return;
 const bool checked=*validated!=0, dirty=*tainted!=0;
 const bool bridge=TahoeDescriptor::admitted(data,offset,checked,dirty,runningBuild) && pathMatches(vnode,TahoeDescriptor::image);
 const bool video=!bridge && TahoeDescriptor::videoAdmitted(data,offset,checked,dirty,runningBuild) && pathMatches(vnode,TahoeDescriptor::videoImage);
 auto site=!bridge && !video ? TahoeDescriptor::driverSite(data,offset,checked,dirty,runningBuild) : nullptr;
 if(site && !pathMatches(vnode,TahoeDescriptor::driverImage))site=nullptr;
 const bool metal=!bridge && !video && !site && TahoeDescriptor::metalAdmitted(data,offset,checked,dirty,runningBuild) && pathMatches(vnode,TahoeDescriptor::metalImage);
 if((!bridge && !video && !site && !metal) || MachInfo::setKernelWriting(true,KernelPatcher::kernelWriteLock)!=KERN_SUCCESS)return;
 auto page=static_cast<uint8_t *>(const_cast<void *>(data));
 if(bridge)TahoeDescriptor::apply(page);
 else if(video)TahoeDescriptor::applyVideo(page);
 else if(metal)TahoeDescriptor::applyMetal(page);
 else TahoeDescriptor::applyDriver(page,*site);
 MachInfo::setKernelWriting(false,KernelPatcher::kernelWriteLock);
 SYSLOG("wex","Tahoe %s admitted for %s",bridge ? "descriptor bridge" : video ? "video adapter" : metal ? "GPU counters" : "pixel transfer",runningBuild);
}
}

void TahoeDescriptor::processKernel(KernelPatcher &p) {
 if(getKernelVersion()!=KernelVersion::Tahoe)return;
 getPath=reinterpret_cast<decltype(getPath)>(p.solveSymbol(KernelPatcher::KernelID,"_vn_getpath"));
 p.clearError();
 runningBuild=reinterpret_cast<const char *>(p.solveSymbol(KernelPatcher::KernelID,"_osversion"));
 p.clearError();
 bool ready=false;
 if(getPath && runningBuild) {
  KernelPatcher::RouteRequest route {"_cs_validate_page",validatePage,originalValidate};
  ready=p.routeMultipleLong(KernelPatcher::KernelID,&route,1);
  p.clearError();
 }
 IORegistryEntry::getRegistryRoot()->setProperty("WhateverXeTahoeDescriptor",ready);
 if(ready)IORegistryEntry::getRegistryRoot()->setProperty("WhateverXeVideoTransfer","software");
 SYSLOG("wex","Tahoe descriptor hook ready=%d",ready);
 if(ready)SYSLOG("wex","video pixel transfer has no hardware path: software conversion in use");
}
