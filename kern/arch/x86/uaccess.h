/* Copyright (c) 2015 Google Inc
 * Davide Libenzi <dlibenzi@google.com>
 * See LICENSE for details.
 *
 * Part of this code coming from a Linux kernel file:
 *
 * linux/arch/x86/include/asm/uaccess.h
 *
 * Which, even though missing specific copyright, it is supposed to be
 * ruled by the overall Linux copyright.
 */

#pragma once

#include <ros/errno.h>
#include <compiler.h>
#include <stdint.h>
#include <umem.h>

#define ASM_STAC
#define ASM_CLAC
#define __m(x) *(x)

struct extable_ip_fixup {
	uint64_t insn;
	uint64_t fixup;
};

#define _ASM_EXTABLE_INIT()										\
	asm volatile(												\
	" .pushsection \"__ex_table\",\"a\"\n"						\
	" .balign 16\n"												\
	" .popsection\n"											\
	: :)

#define _ASM_EXTABLE(from, to)									\
	" .pushsection \"__ex_table\",\"a\"\n"						\
	" .balign 16\n"												\
	" .quad (" #from ") - .\n"									\
	" .quad (" #to ") - .\n"									\
	" .popsection\n"

#define __put_user_asm(x, addr, err, itype, rtype, ltype, errret)       \
	asm volatile(ASM_STAC "\n"											\
				 "1:        mov"itype" %"rtype"1,%2\n"					\
	             "2: " ASM_CLAC "\n"									\
				 ".section .fixup,\"ax\"\n"								\
				 "3:        mov %3,%0\n"								\
				 "  jmp 2b\n"											\
				 ".previous\n"											\
				 _ASM_EXTABLE(1b, 3b)									\
				 : "=r"(err)											\
				 : ltype(x), "m" (__m(addr)), "i" (errret), "0" (err))

#define __get_user_asm(x, addr, err, itype, rtype, ltype, errret)	\
	asm volatile(ASM_STAC "\n"                                      \
				 "1:        mov"itype" %2,%"rtype"1\n"              \
				 "2: " ASM_CLAC "\n"                                \
				 ".section .fixup,\"ax\"\n"							\
				 "3:        mov %3,%0\n"                            \
				 "  xor"itype" %"rtype"1,%"rtype"1\n"               \
				 "  jmp 2b\n"                                       \
				 ".previous\n"                                      \
				 _ASM_EXTABLE(1b, 3b)                               \
				 : "=r" (err), ltype(x)                             \
				 : "m" (__m(addr)), "i" (errret), "0" (err))

#define __user_memcpy(dst, src, count, err, errret)						\
	asm volatile(ASM_STAC "\n"											\
				 "1:        rep movsb\n"								\
	             "2: " ASM_CLAC "\n"									\
				 ".section .fixup,\"ax\"\n"								\
				 "3:        mov %4,%0\n"								\
				 "  jmp 2b\n"											\
				 ".previous\n"											\
				 _ASM_EXTABLE(1b, 3b)									\
				 : "=r"(err)											\
				 : "D" (dst), "S" (src), "c" (count), "i" (errret), "0" (err))

static inline int copy_to_user(void *dst, const void *src, unsigned int count)
{
	int err = 0;

	if (unlikely(!is_user_rwaddr(dst, count))) {
		err = -EFAULT;
	} else if (!__builtin_constant_p(count)) {
		__user_memcpy(dst, src, count, err, -EFAULT);
	} else {
		switch (count) {
		case 1:
			__put_user_asm(*(const uint8_t *) src, (uint8_t *) dst, err, "b",
						   "b", "iq", -EFAULT);
			break;
		case 2:
			__put_user_asm(*(const uint16_t *) src, (uint16_t *) dst, err, "w",
						   "w", "ir", -EFAULT);
			break;
		case 4:
			__put_user_asm(*(const uint32_t *) src, (uint32_t *) dst, err, "l",
						   "k", "ir", -EFAULT);
			break;
		case 8:
			__put_user_asm(*(const uint64_t *) src, (uint64_t *) dst, err, "q",
						   "", "er", -EFAULT);
			break;
		default:
			__user_memcpy(dst, src, count, err, -EFAULT);
		}
	}

	return err;
}

static inline int copy_from_user(void *dst, const void *src,
								 unsigned int count)
{
	int err = 0;

	if (unlikely(!is_user_raddr((void *) src, count))) {
		err = -EFAULT;
	} else if (!__builtin_constant_p(count)) {
		__user_memcpy(dst, src, count, err, -EFAULT);
	} else {
		switch (count) {
		case 1:
			__get_user_asm(*(uint8_t *) dst, (const uint8_t *) src, err, "b",
						   "b", "=q", -EFAULT);
			break;
		case 2:
			__get_user_asm(*(uint16_t *) dst, (const uint16_t *) src, err, "w",
						   "w", "=r", -EFAULT);
			break;
		case 4:
			__get_user_asm(*(uint32_t *) dst, (const uint32_t *) src, err, "l",
						   "k", "=r", -EFAULT);
			break;
		case 8:
			__get_user_asm(*(uint64_t *) dst, (const uint64_t *) src, err, "q",
						   "", "=r", -EFAULT);
			break;
		default:
			__user_memcpy(dst, src, count, err, -EFAULT);
		}
	}

	return err;
}

static inline uintptr_t ex_insn_addr(const struct extable_ip_fixup *x)
{
	return (uintptr_t) &x->insn + x->insn;
}

static inline uintptr_t ex_fixup_addr(const struct extable_ip_fixup *x)
{
	return (uintptr_t) &x->fixup + x->fixup;
}
