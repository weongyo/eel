/*-
 * Copyright (c) 2006-2010 Redpill Linpro AS
 * All rights reserved.
 *
 * Author: Poul-Henning Kamp <phk@phk.freebsd.dk>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * ctype(3) like functions, according to RFC2616
 */

#include <stdint.h>

/* NB: VCT always operate in ASCII, don't replace 0x0d with \r etc. */

#define VCT_UPALPHA	VCT_ALPHA
#define VCT_LOALPHA	VCT_ALPHA

const uint16_t vct_typtab[256] = {
        0x4,
        0x4,
        0x4,
        0x4,
        0x4,
        0x4,
        0x4,
        0x4,
        0x4,
        0x15,
        0x6,
        0x4,
        0x4,
        0x6,
        0x4,
        0x4,
        0x4,
        0x4,
        0x4,
        0x4,
        0x4,
        0x4,
        0x4,
        0x4,
        0x4,
        0x4,
        0x4,
        0x4,
        0x4,
        0x4,
        0x4,
        0x4,
        0x11,
        0,
        0x10,
        0,
        0,
        0,
        0,
        0,
        0x10,
        0x10,
        0,
        0,
        0x10,
        0x100,
        0x100,
        0x10,
        0x160,
        0x160,
        0x160,
        0x160,
        0x160,
        0x160,
        0x160,
        0x160,
        0x160,
        0x160,
        0x90,
        0x10,
        0x10,
        0x10,
        0x10,
        0x10,
        0x10,
        0xc8,
        0xc8,
        0xc8,
        0xc8,
        0xc8,
        0xc8,
        0x88,
        0x88,
        0x88,
        0x88,
        0x88,
        0x88,
        0x88,
        0x88,
        0x88,
        0x88,
        0x88,
        0x88,
        0x88,
        0x88,
        0x88,
        0x88,
        0x88,
        0x88,
        0x88,
        0x88,
        0x10,
        0x10,
        0x10,
        0,
        0x80,
        0,
        0xc8,
        0xc8,
        0xc8,
        0xc8,
        0xc8,
        0xc8,
        0x88,
        0x88,
        0x88,
        0x88,
        0x88,
        0x88,
        0x88,
        0x88,
        0x88,
        0x88,
        0x88,
        0x88,
        0x88,
        0x88,
        0x88,
        0x88,
        0x88,
        0x88,
        0x88,
        0x88,
        0x10,
        0,
        0x10,
        0,
        0x4,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0x100,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0x80,
        0x80,
        0x80,
        0x80,
        0x80,
        0x80,
        0x80,
        0x80,
        0x80,
        0x80,
        0x80,
        0x80,
        0x80,
        0x80,
        0x80,
        0x80,
        0x80,
        0x80,
        0x80,
        0x80,
        0x80,
        0x80,
        0x80,
        0,
        0x80,
        0x80,
        0x80,
        0x80,
        0x80,
        0x80,
        0x80,
        0x80,
        0x80,
        0x80,
        0x80,
        0x80,
        0x80,
        0x80,
        0x80,
        0x80,
        0x80,
        0x80,
        0x80,
        0x80,
        0x80,
        0x80,
        0x80,
        0x80,
        0x80,
        0x80,
        0x80,
        0x80,
        0x80,
        0x80,
        0x80,
        0,
        0x80,
        0x80,
        0x80,
        0x80,
        0x80,
        0x80,
        0x80,
        0x80,
};
