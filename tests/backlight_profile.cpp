#include "kern_backlight_profile.hpp"
#include <cassert>
#include <cstdio>
int main() {
 using namespace XeBacklightProfile;
 // The native T profile is a big-endian count followed by that many levels.
 const unsigned count=(curve[0]<<8)|curve[1];
 assert(sizeof(curve)==2+2*count);
 unsigned previous=0;
 for(unsigned i=0;i<count;++i) {
  const unsigned value=(curve[2+2*i]<<8)|curve[3+2*i];
  assert(i ? value>previous : value==654);previous=value; // Never fully off.
 }
 assert(previous>65000 && previous<=65535);
 assert(eligible(19,0,65535,true));
 for(unsigned uid=0;uid<256;++uid)assert(eligible(uid,0,65535,true)==(uid==19));
 assert(!eligible(19,0,65535,false));
 assert(!eligible(19,1,65535,true));
 assert(!eligible(19,0,0,true));assert(!eligible(19,0,65536,true));
 puts("PASS: profile shape, monotonic levels, UID/range/internal eligibility");
}
