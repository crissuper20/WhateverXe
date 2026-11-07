# EXPERIMENT (-wex-tgl-vp9): VP9 decoder factory stub for AppleIntelTGLGraphicsVADriver
# (25G332 payload). It lives at 0xC70 in the Mach-O header pad, inside the zero gap
# 0xC6E-0xD2F between the patch snippets already in that pad. The factory's skip
# branch for subtypes it does not build (jne 0x149a5 at 0x144e2) jumps here instead.
# Subtype 0x1000 (VP9) with an empty slot calls WEXVP9Create(context, config) from
# @loader_path/WEXVP9.dylib. A decoder (non-NULL result) goes into the factory's decoder
# slot and continues where a native decoder whose create succeeded does (0x149a8,
# r12d = 0, as the 0x400 case at 0x148bb). A missing library or symbol, or a NULL result, fails the request through the
# factory's own error exit (0x15072, ebx = 1), as when no advertised config matches, so
# VideoToolbox creates no hardware VP9 session without a decoder behind it.
# Regenerate the bytes in kern_tahoe_descriptor_policy.hpp with tools/vp9/gen-stub.py.
	.set CAVE, 0xc70
	.set SKIP, 0x149a5     # original jne target
	.set DLOPEN, 0x23e380  # __stubs: _dlopen
	.set DLSYM, 0x23e386   # __stubs: _dlsym
	.set NEXT, 0x149a8     # native success: next config node
	.set FAIL, 0x15072     # error exit: releases the perf capability, frees, returns ebx
	.text
Lstart:
	cmpq	$0x1000, %rax          # subtype; 0x200/0x400/0x800 were already taken
	jne	Lstart + (SKIP - CAVE)
	movq	(%r9), %rax            # same empty-slot test as every native case
	cmpq	$0, (%rax,%r15,8)
	jne	Lstart + (SKIP - CAVE)
	pushq	%rsi                   # live across the skip: esi, r8, r9 (rsp stays 16-aligned)
	pushq	%r9
	pushq	%r8
	pushq	%rdi
	pushq	%rdx
	pushq	%rcx
	pushq	%r10
	pushq	%r11
	leaq	Lpath(%rip), %rdi
	movl	$2, %esi               # RTLD_NOW
	callq	Lstart + (DLOPEN - CAVE)
	testq	%rax, %rax
	je	Ldone                  # rax = 0: fail
	movq	%rax, %rdi
	leaq	Lsymbol(%rip), %rsi
	callq	Lstart + (DLSYM - CAVE)
	testq	%rax, %rax
	je	Ldone
	movq	-0x168(%rbp), %rdi     # context, as native create(context, config)
	movq	%r14, %rsi             # config node
	callq	*%rax
Ldone:
	popq	%r11
	popq	%r10
	popq	%rcx
	popq	%rdx
	popq	%rdi
	popq	%r8
	popq	%r9
	popq	%rsi
	testq	%rax, %rax
	je	Lfail
	movq	(%r9), %rcx            # slot array; rcx is dead here, as after a native create call
	movq	%rax, (%rcx,%r15,8)
	xorl	%r12d, %r12d
	jmp	Lstart + (NEXT - CAVE)
Lfail:
	movl	$1, %ebx               # no decoder: fail like an unmatched config
	jmp	Lstart + (FAIL - CAVE)
Lpath:
	.asciz	"@loader_path/WEXVP9.dylib"
Lsymbol:
	.asciz	"WEXVP9Create"
