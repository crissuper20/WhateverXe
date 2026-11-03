#!/usr/bin/env python3
"""Each heap depth gate patch only turns the je after the +0x19C HiZ test into a two-byte nop."""
from pathlib import Path
import re
repo=Path(__file__).resolve().parents[1]
source=(repo/'WhateverXe/kern_xe.cpp').read_text()
table=re.search(r'tglHeapDepthGates\[2\] \{(.*?)\n\};',source,re.S).group(1)
gates=re.findall(r'\{(0x[0-9A-F]+),\{([^}]*)\},\s*(?://[^\n]*)?\s*\{([^}]*)\}\}',table)
assert len(gates)==2,gates
offsets=[]
for offset,before,after in gates:
    before=[int(v,16) for v in before.split(',')];after=[int(v,16) for v in after.split(',')]
    assert len(before)==len(after)==16
    changed=[i for i in range(16) if before[i]!=after[i]]
    assert len(changed)==2 and changed[1]==changed[0]+1,changed
    i=changed[0]
    assert before[i]==0x74 and after[i:i+2]==[0x66,0x90]
    # The je follows the driver's cmpl $0x0,0x19C(reg).
    assert bytes(before[:i]).endswith(b'\x9c\x01\x00\x00\x00')
    offsets.append((int(offset,16),bytes(before)))
kext=Path('/Library/Extensions/AppleIntelTGLGraphics.kext/Contents/MacOS/AppleIntelTGLGraphics')
if kext.exists():
    data=kext.read_bytes()
    if all(data[o:o+16]==b for o,b in offsets):print('local driver matches both gate sites')
    else:print('local driver differs; gates stay unpatched there')
print('only the two HiZ skip branches change')
