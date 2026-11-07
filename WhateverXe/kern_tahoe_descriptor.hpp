// Copyright (c) 2026 b00t0x. BSD-3-Clause.
#pragma once
#include <Headers/kern_patcher.hpp>
namespace TahoeDescriptor {
void processKernel(KernelPatcher &patcher);
// EXPERIMENT (-wex-tgl-vp9): flag set and the page hook ready.
bool vp9Requested();
}
