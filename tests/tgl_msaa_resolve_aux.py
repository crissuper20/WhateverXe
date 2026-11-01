#!/usr/bin/env python3
"""The OpenGL resolve source loses only aux mode 5, and only when multisampled."""
from pathlib import Path
import re,subprocess,tempfile
repo=Path(__file__).resolve().parents[1]
source=(repo/'WhateverXe/kern_xe.cpp').read_text()
helper=re.search(r'static bool tglClearResolveSourceAux\(uint32_t \*w\) \{.*?\n\}',source,re.S).group()
code=r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
HELPER
int main() {
 uint32_t w[16];memset(w,0x5A,sizeof(w));
 w[4]=1<<3;w[6]=(14<<3)|5;
 uint32_t saved[16];memcpy(saved,w,sizeof(w));
 assert(tglClearResolveSourceAux(w));assert(w[6]==(14<<3));
 saved[6]=w[6];assert(!memcmp(w,saved,sizeof(w)));
 assert(!tglClearResolveSourceAux(w));
 for(uint32_t aux=0;aux<8;aux++) if(aux!=5) {
  w[6]=aux;assert(!tglClearResolveSourceAux(w));assert(w[6]==aux);
 }
 w[4]=0;w[6]=5;assert(!tglClearResolveSourceAux(w));assert(w[6]==5);
 puts("only multisampled aux mode 5 changes");
}
'''.replace('HELPER',helper)
with tempfile.TemporaryDirectory(prefix='tgl-msaa-resolve-') as tmp:
    src=Path(tmp)/'check.cpp';exe=Path(tmp)/'check'
    src.write_text(code)
    subprocess.run(['clang++','-std=c++14','-O2',str(src),'-o',str(exe)],check=True)
    subprocess.run([str(exe)],check=True)
