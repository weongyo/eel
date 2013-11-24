/*-
 * Copyright (c) 1988, 1989, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)radix.h	8.2 (Berkeley) 10/31/94
 * $FreeBSD$
 */

#include "config.h"

#include <sys/param.h>
#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "eel.h"
#include "radix.h"

/*
 * Most of the functions in this code assume that the key argument
 * is special structures, where the first two bytes are an u_short
 * indicating the size of the entire structure.
 *
 * To make the assumption more explicit, we use the LEN() macro to access
 * this field. It is safe to pass an expression with side effects
 * to LEN() as the argument is evaluated only once.
 * We cast the result to int as this is the dominant usage.
 */
#define LEN(x) ( (int) (*(const u_short *)(x)) )

/*-------------------------------------------------------------------------*/

#define MKGet(m) {						\
	if (rn_mkfreelist) {					\
		m = rn_mkfreelist;				\
		rn_mkfreelist = (m)->rm_mklist;			\
	} else							\
		R_Malloc(m, struct radix_mask *, sizeof (struct radix_mask)); }
 
#define MKFree(m) { (m)->rm_mklist = rn_mkfreelist; rn_mkfreelist = (m);}

static int	max_keylen;
static struct radix_mask *rn_mkfreelist;
/*
 * Work area -- the following point to 3 buffers of size max_keylen,
 * allocated in this order in a block of memory malloc'ed by rn_init.
 * rn_zeros, rn_ones are set in rn_init and used in readonly afterwards.
 */
static char *rn_zeros, *rn_ones;

static struct radix_node
		 *rn_add (void *, struct radix_node_head *,
				struct radix_node [2]),
		 *rn_delete(void *, struct radix_node_head *),
		 *rn_match(void *, struct radix_node_head *);
static struct radix_node *
		rn_newpair(void *v, int b, struct radix_node nodes[2]);

/*
 * XXX THIS NEEDS TO BE FIXED
 * In the code, pointers to keys and masks are passed as either
 * 'void *' (because callers use to pass pointers of various kinds), or
 * 'caddr_t' (which is fine for pointer arithmetics, but not very
 * clean when you dereference it to access data). Furthermore, caddr_t
 * is really 'char *', while the natural type to operate on keys and
 * masks would be 'u_char'. This mismatch require a lot of casts and
 * intermediate variables to adapt types that clutter the code.
 */

/*
 * Search a node in the tree matching the key.
 */
static struct radix_node *
rn_search(void *v_arg, struct radix_node *head)
{
	register struct radix_node *x;
	register caddr_t v;

	for (x = head, v = v_arg; x->rn_bit >= 0;) {
		if (x->rn_bmask & v[x->rn_offset])
			x = x->rn_right;
		else
			x = x->rn_left;
	}
	return (x);
}

static struct radix_node *
rn_insert(void *v_arg, struct radix_node_head *head, int *dupentry,
    struct radix_node nodes[2])
{
	caddr_t v = v_arg;
	struct radix_node *top = head->rnh_treetop;
	int head_off = top->rn_offset, vlen = LEN(v);
	register struct radix_node *t = rn_search(v_arg, top);
	register caddr_t cp = v + head_off;
	register int b;
	struct radix_node *tt;
    	/*
	 * Find first bit at which v and t->rn_key differ
	 */
    {
	register caddr_t cp2 = t->rn_key + head_off;
	register int cmp_res;
	caddr_t cplim = v + vlen;

	while (cp < cplim)
		if (*cp2++ != *cp++)
			goto on1;
	*dupentry = 1;
	return t;
on1:
	*dupentry = 0;
	cmp_res = (cp[-1] ^ cp2[-1]) & 0xff;
	for (b = (cp - v) << 3; cmp_res; b--)
		cmp_res >>= 1;
    }
    {
	register struct radix_node *p, *x = top;
	cp = v;
	do {
		p = x;
		if (cp[x->rn_offset] & x->rn_bmask)
			x = x->rn_right;
		else
			x = x->rn_left;
	} while (b > (unsigned) x->rn_bit);
				/* x->rn_bit < b && x->rn_bit >= 0 */
	t = rn_newpair(v_arg, b, nodes); 
	tt = t->rn_left;
	if ((cp[p->rn_offset] & p->rn_bmask) == 0)
		p->rn_left = t;
	else
		p->rn_right = t;
	x->rn_parent = t;
	t->rn_parent = p; /* frees x, p as temp vars below */
	if ((cp[t->rn_offset] & t->rn_bmask) == 0) {
		t->rn_right = x;
	} else {
		t->rn_right = tt;
		t->rn_left = x;
	}
    }
	return (tt);
}

static struct radix_node *
rn_add(void *v_arg, struct radix_node_head *head,
    struct radix_node treenodes[2])
{
	caddr_t v = (caddr_t)v_arg;
	register struct radix_node *t, *x = 0, *tt;
	struct radix_node *saved_tt;
	short b_leaf = 0;
	int keyduplicated;
	struct radix_mask *m, **mp;

	/*
	 * Deal with duplicated keys: attach node to previous instance
	 */
	saved_tt = tt = rn_insert(v, head, &keyduplicated, treenodes);
	if (keyduplicated) {
		for (t = tt; tt; t = tt, tt = tt->rn_dupedkey) {
			if (tt->rn_mask == NULL)
				return (0);
			break;
		}
		/*
		 * If the mask is not duplicated, we wouldn't
		 * find it among possible duplicate key entries
		 * anyway, so the above test doesn't hurt.
		 *
		 * We sort the masks for a duplicated key the same way as
		 * in a masklist -- most specific to least specific.
		 * This may require the unfortunate nuisance of relocating
		 * the head of the list.
		 *
		 * We also reverse, or doubly link the list through the
		 * parent pointer.
		 */
		if (tt == saved_tt) {
			struct	radix_node *xx = x;
			/* link in at head of list */
			(tt = treenodes)->rn_dupedkey = t;
			tt->rn_flags = t->rn_flags;
			tt->rn_parent = x = t->rn_parent;
			t->rn_parent = tt;	 		/* parent */
			if (x->rn_left == t)
				x->rn_left = tt;
			else
				x->rn_right = tt;
			saved_tt = tt; x = xx;
		} else {
			(tt = treenodes)->rn_dupedkey = t->rn_dupedkey;
			t->rn_dupedkey = tt;
			tt->rn_parent = t;			/* parent */
			if (tt->rn_dupedkey)			/* parent */
				tt->rn_dupedkey->rn_parent = tt; /* parent */
		}
		tt->rn_key = (caddr_t) v;
		tt->rn_bit = -1;
		tt->rn_flags = RNF_ACTIVE;
	}
	t = saved_tt->rn_parent;
	if (keyduplicated)
		goto on2;
	b_leaf = -1 - t->rn_bit;
	if (t->rn_right == saved_tt)
		x = t->rn_left;
	else
		x = t->rn_right;
	/* Promote general routes from below */
	if (x->rn_bit < 0) {
		for (mp = &t->rn_mklist; x; x = x->rn_dupedkey)
			assert(x->rn_mask == 0);
	} else if (x->rn_mklist) {
		/*
		 * Skip over masks whose index is > that of new node
		 */
		for (mp = &x->rn_mklist; (m = *mp); mp = &m->rm_mklist)
			if (m->rm_bit >= b_leaf)
				break;
		t->rn_mklist = m; *mp = 0;
	}
on2:
	return tt; /* can't lift at all */
}

static struct radix_node *
rn_delete(void *v_arg, struct radix_node_head *head)
{
	register struct radix_node *t, *p, *x, *tt;
	struct radix_mask *m, **mp;
	struct radix_node *dupedkey, *saved_tt;
	caddr_t v;
	int head_off, vlen;

	v = v_arg;
	x = head->rnh_treetop;
	tt = rn_search(v, x);
	head_off = x->rn_offset;
	vlen = LEN(v);
	saved_tt = tt;
	if (tt == 0 ||
	    bcmp(v + head_off, tt->rn_key + head_off, vlen - head_off))
		return (0);
	assert(tt->rn_mask == 0);
	/*
	 * Eliminate us from tree
	 */
	if (tt->rn_flags & RNF_ROOT)
		return (0);
	t = tt->rn_parent;
	dupedkey = saved_tt->rn_dupedkey;
	if (dupedkey) {
		/*
		 * Here, tt is the deletion target and
		 * saved_tt is the head of the dupekey chain.
		 */
		if (tt == saved_tt) {
			/* remove from head of chain */
			x = dupedkey; x->rn_parent = t;
			if (t->rn_left == tt)
				t->rn_left = x;
			else
				t->rn_right = x;
		} else {
			/* find node in front of tt on the chain */
			for (x = p = saved_tt; p && p->rn_dupedkey != tt;)
				p = p->rn_dupedkey;
			if (p) {
				p->rn_dupedkey = tt->rn_dupedkey;
				if (tt->rn_dupedkey)		/* parent */
					tt->rn_dupedkey->rn_parent = p;
								/* parent */
			} else
				printf("rn_delete: couldn't find us\n");
		}
		t = tt + 1;
		if  (t->rn_flags & RNF_ACTIVE) {
			*++x = *t;
			p = t->rn_parent;
			if (p->rn_left == t)
				p->rn_left = x;
			else
				p->rn_right = x;
			x->rn_left->rn_parent = x;
			x->rn_right->rn_parent = x;
		}
		goto out;
	}
	if (t->rn_left == tt)
		x = t->rn_right;
	else
		x = t->rn_left;
	p = t->rn_parent;
	if (p->rn_right == t)
		p->rn_right = x;
	else
		p->rn_left = x;
	x->rn_parent = p;
	/*
	 * Demote routes attached to us.
	 */
	if (t->rn_mklist) {
		if (x->rn_bit >= 0) {
			for (mp = &x->rn_mklist; (m = *mp);)
				mp = &m->rm_mklist;
			*mp = t->rn_mklist;
		} else {
			/* If there are any key,mask pairs in a sibling
			   duped-key chain, some subset will appear sorted
			   in the same order attached to our mklist */
			for (m = t->rn_mklist; m && x; x = x->rn_dupedkey)
				if (m == x->rn_mklist) {
					struct radix_mask *mm = m->rm_mklist;
					x->rn_mklist = 0;
					if (--(m->rm_refs) < 0)
						MKFree(m);
					m = mm;
				}
			if (m)
				printf(
				    "rn_delete: Orphaned Mask %p at %p\n",
				    m, x);
		}
	}
	/*
	 * We may be holding an active internal node in the tree.
	 */
	x = tt + 1;
	if (t != x) {
		*t = *x;
		t->rn_left->rn_parent = t;
		t->rn_right->rn_parent = t;
		p = x->rn_parent;
		if (p->rn_left == x)
			p->rn_left = t;
		else
			p->rn_right = t;
	}
out:
	tt->rn_flags &= ~RNF_ACTIVE;
	tt[1].rn_flags &= ~RNF_ACTIVE;
	return (tt);
}

static int
rn_satisfies_leaf(char *trial, register struct radix_node *leaf, int skip)
{
	register char *cp = trial, *cp2 = leaf->rn_key, *cp3 = leaf->rn_mask;
	char *cplim;
	int length = MIN(LEN(cp), LEN(cp2));

	if (cp3 == NULL)
		cp3 = rn_ones;
	else
		length = MIN(length, LEN(cp3));
	cplim = cp + length; cp3 += skip; cp2 += skip;
	for (cp += skip; cp < cplim; cp++, cp2++, cp3++)
		if ((*cp ^ *cp2) & *cp3)
			return 0;
	return 1;
}

/*
 * Same as above, but with an additional mask.
 * XXX note this function is used only once.
 */
static struct radix_node *
rn_search_m(void *v_arg, struct radix_node *head, void *m_arg)
{
	register struct radix_node *x;
	register caddr_t v = v_arg, m = m_arg;

	for (x = head; x->rn_bit >= 0;) {
		if ((x->rn_bmask & m[x->rn_offset]) &&
		    (x->rn_bmask & v[x->rn_offset]))
			x = x->rn_right;
		else
			x = x->rn_left;
	}
	return x;
}

static struct radix_node *
rn_match(void *v_arg, struct radix_node_head *head)
{
	caddr_t v = v_arg;
	register struct radix_node *t = head->rnh_treetop, *x;
	register caddr_t cp = v, cp2;
	caddr_t cplim;
	struct radix_node *saved_t, *top = t;
	int off = t->rn_offset, vlen = LEN(cp), matched_off;
	register int test, b, rn_bit;

	/*
	 * Open code rn_search(v, top) to avoid overhead of extra
	 * subroutine call.
	 */
	for (; t->rn_bit >= 0; ) {
		if (t->rn_bmask & cp[t->rn_offset])
			t = t->rn_right;
		else
			t = t->rn_left;
	}
	/*
	 * See if we match exactly as a key
	 * or at least learn how many bits match, for normal mask finesse.
	 *
	 * It doesn't hurt us to limit how many bytes to check
	 * to the length of the mask, since if it matches we had a genuine
	 * match and the leaf we have is the most specific one anyway;
	 * if it didn't match with a shorter length it would fail
	 * with a long one.  This wins big for class B&C netmasks which
	 * are probably the most common case...
	 */
	assert(t->rn_mask == NULL);
	cp += off; cp2 = t->rn_key + off; cplim = v + vlen;
	for (; cp < cplim; cp++, cp2++)
		if (*cp != *cp2)
			goto on1;
	/*
	 * This extra grot is in case we are explicitly asked
	 * to look up the default.  Ugh!
	 *
	 * Never return the root node itself, it seems to cause a
	 * lot of confusion.
	 */
	if (t->rn_flags & RNF_ROOT)
		t = t->rn_dupedkey;
	return t;
on1:
	test = (*cp ^ *cp2) & 0xff; /* find first bit that differs */
	for (b = 7; (test >>= 1) > 0;)
		b--;
	matched_off = cp - v;
	b += matched_off << 3;
	rn_bit = -1 - b;
	/*
	 * If there is a host route in a duped-key chain, it will be first.
	 */
	if ((saved_t = t)->rn_mask == 0)
		t = t->rn_dupedkey;
	for (; t; t = t->rn_dupedkey)
		/*
		 * Even if we don't match exactly as a host,
		 * we may match if the leaf we wound up at is
		 * a route to a net.
		 */
		if (t->rn_flags & RNF_NORMAL) {
			if (rn_bit <= t->rn_bit)
				return t;
		} else if (rn_satisfies_leaf(v, t, matched_off))
				return t;
	t = saved_t;
	/* start searching up the tree */
	do {
		register struct radix_mask *m;
		t = t->rn_parent;
		m = t->rn_mklist;
		/*
		 * If non-contiguous masks ever become important
		 * we can restore the masking and open coding of
		 * the search and satisfaction test and put the
		 * calculation of "off" back before the "do".
		 */
		while (m) {
			if (m->rm_flags & RNF_NORMAL) {
				if (rn_bit <= m->rm_bit)
					return (m->rm_leaf);
			} else {
				off = MIN(t->rn_offset, matched_off);
				x = rn_search_m(v, t, m->rm_mask);
				while (x && x->rn_mask != m->rm_mask)
					x = x->rn_dupedkey;
				if (x && rn_satisfies_leaf(v, x, off))
					return x;
			}
			m = m->rm_mklist;
		}
	} while (t != top);
	return 0;
}

static int
rn_walktree(struct radix_node_head *h, walktree_f_t *f, void *w)
{
	int error;
	struct radix_node *base, *next;
	register struct radix_node *rn = h->rnh_treetop;
	/*
	 * This gets complicated because we may delete the node
	 * while applying the function f to it, so we need to calculate
	 * the successor node in advance.
	 */

	/* First time through node, go left */
	while (rn->rn_bit >= 0)
		rn = rn->rn_left;
	for (;;) {
		base = rn;
		/* If at right child go back up, otherwise, go right */
		while (rn->rn_parent->rn_right == rn
		       && (rn->rn_flags & RNF_ROOT) == 0)
			rn = rn->rn_parent;
		/* Find the next *leaf* since next node might vanish, too */
		for (rn = rn->rn_parent->rn_right; rn->rn_bit >= 0;)
			rn = rn->rn_left;
		next = rn;
		/* Process leaves */
		while ((rn = base)) {
			base = rn->rn_dupedkey;
			if (!(rn->rn_flags & RNF_ROOT)
			    && (error = (*f)(rn, w)))
				return (error);
		}
		rn = next;
		if (rn->rn_flags & RNF_ROOT)
			return (0);
	}
	/* NOTREACHED */
}

/*
 * Whenever we add a new leaf to the tree, we also add a parent node,
 * so we allocate them as an array of two elements: the first one must be
 * the leaf, the second one is the parent.
 * This routine initializes the relevant fields of the nodes, so that
 * the leaf is the left child of the parent node, and both nodes have
 * (almost) all all fields filled as appropriate.
 * (XXX some fields are left unset, see the '#if 0' section).
 * The function returns a pointer to the parent node.
 */

static struct radix_node *
rn_newpair(void *v, int b, struct radix_node nodes[2])
{
	register struct radix_node *tt = nodes, *t = tt + 1;
	t->rn_bit = b;
	t->rn_bmask = 0x80 >> (b & 7);
	t->rn_left = tt;
	t->rn_offset = b >> 3;

#if 0  /* XXX perhaps we should fill these fields as well. */
	t->rn_parent = t->rn_right = NULL;

	tt->rn_mask = NULL;
	tt->rn_dupedkey = NULL;
	tt->rn_bmask = 0;
#endif
	tt->rn_bit = -1;
	tt->rn_key = (caddr_t)v;
	tt->rn_parent = t;
	tt->rn_flags = t->rn_flags = RNF_ACTIVE;
	tt->rn_mklist = t->rn_mklist = 0;
	return t;
}

/*
 * Allocate and initialize an empty tree. This has 3 nodes, which are
 * part of the radix_node_head (in the order <left,root,right>) and are
 * marked RNF_ROOT so they cannot be freed.
 * The leaves have all-zero and all-one keys, with significant
 * bits starting at 'off'.
 * Return 1 on success, 0 on error.
 */
int
rn_inithead(head, off)
	void **head;
	int off;
{
	register struct radix_node_head *rnh;
	register struct radix_node *t, *tt, *ttt;
	if (*head)
		return (1);
	R_Zalloc(rnh, struct radix_node_head *, sizeof (*rnh));
	if (rnh == 0)
		return (0);
	RADIX_NODE_HEAD_LOCK_INIT(rnh);
	*head = rnh;
	t = rn_newpair(rn_zeros, off, rnh->rnh_nodes);
	ttt = rnh->rnh_nodes + 2;
	t->rn_right = ttt;
	t->rn_parent = t;
	tt = t->rn_left;	/* ... which in turn is rnh->rnh_nodes */
	tt->rn_flags = t->rn_flags = RNF_ROOT | RNF_ACTIVE;
	tt->rn_bit = -1 - off;
	*ttt = *tt;
	ttt->rn_key = rn_ones;
	rnh->rnh_add = rn_add;
	rnh->rnh_del = rn_delete;
	rnh->rnh_match = rn_match;
	rnh->rnh_walktree = rn_walktree;
	rnh->rnh_treetop = t;
	return (1);
}

void
rn_init(int maxk)
{
	char *cp, *cplim;

	max_keylen = maxk;
	if (max_keylen == 0) {
		printf("rn_init: radix functions require max_keylen be set\n");
		return;
	}
	R_Malloc(rn_zeros, char *, 3 * max_keylen);
	if (rn_zeros == NULL)
		abort();
	bzero(rn_zeros, 3 * max_keylen);
	rn_ones = cp = rn_zeros + max_keylen;
	cplim = rn_ones + max_keylen;
	while (cp < cplim)
		*cp++ = -1;
}