/*
 * qp-trie - a DNS-specific quelques-bits popcount trie for NSD
 *
 * Written by Tony Finch <dot@dotat.at>
 * See LICENSE for the license.
 */

#include "config.h"

#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include "dname.h"
#include "namedb.h"
#include "qp-trie.h"
#include "qp-bits.h"

#ifdef PACKED_STRUCTS
#error PACKED_STRUCTS does not work with a qp-trie
#endif

/*
 * Convert a domain name into a trie lookup key.
 * Names do not need to be normalized to lower case.
 *
 * The byte_to_bits[] table maps bytes in a DNS name into bit
 * positions in an index word. If the upper 8 bits of a table entry
 * are non-zero, the byte maps to two bit positions. Common hostname
 * characters have the upper 8 bits zero, so they map to only one bit
 * position.
 *
 * Returns the length of the key.
 */
static size_t
dname_to_key(const dname_type *dname, qp_key key) {
	size_t off = 0;
	/* Skip the root label by starting at label 1.  */
	for(size_t lnum = 1; lnum < dname->label_count; lnum++) {
		const uint8_t *lptr = dname_label(dname, lnum);
		const uint8_t *label = label_data(lptr);
		size_t len = label_length(lptr);
		for(size_t c = 0; c < len; c++) {
			uint16_t bits = byte_to_bits[label[c]];
			assert(off < sizeof(qp_key));
			key[off++] = bits & 0xFF;
			// escaped?
			if(bits >> 8)
				key[off++] = bits >> 8;
		}
		key[off++] = SHIFT_NOBYTE;
	}
	// terminator is a double NOBYTE
	key[off] = SHIFT_NOBYTE;
	return(off);
}

/*
 * Iterate over every element
 *
 * Depth of recursion can't be more than 512
 */
void
qp_foreach(qp_node *n, void (*fn)(void *, void *), void *ctx) {
	if(isbranch(n)) {
		qp_weight pos, max;
		__builtin_prefetch(n->ptr);
		max = twigmax(n);
		for(pos = 0; pos < max; pos++)
			qp_foreach(twig(n, pos), fn, ctx);
	} else {
		void *val = (void *)n->index;
		if(val != NULL)
			fn(val, ctx);
	}
}

/*
 * get
 */
void *
qp_get(struct qp_trie *t, const dname_type *dname) {
	qp_node *n = &t->root;
	qp_key key;
	size_t len = dname_to_key(dname, key);
	qp_shift bit;
	while(isbranch(n)) {
		__builtin_prefetch(n->ptr);
		bit = twigbit(n, key, len);
		if(!hastwig(n, bit))
			return(NULL);
		n = twig(n, twigpos(n, bit));
	}
	if(!dname_equal(dname, n->ptr)) {
		return(NULL);
	}
	return((void *)n->index);
}

/*
 * del
 */
void
qp_del(struct qp_trie *t, const dname_type *dname) {
	qp_node *n = &t->root;
	qp_key key;
	size_t len = dname_to_key(dname, key);
	qp_shift bit = 0;
	qp_weight pos, max;
	qp_node *oldt, *newt;
	qp_node *p = NULL;
	while(isbranch(n)) {
		__builtin_prefetch(n->ptr);
		bit = twigbit(n, key, len);
		if(!hastwig(n, bit))
			return;
		p = n; n = twig(n, twigpos(n, bit));
	}
	if(!dname_equal(dname, n->ptr)) {
		return;
	}
	// tree becomes empty
	if(p == NULL) {
		n->ptr = NULL;
		n->index = 0;
		t->count--;
		return;
	}
	// step back to parent node
	n = p; p = NULL;
	assert(bit != 0);
	pos = twigpos(n, bit);
	max = twigmax(n);
	oldt = n->ptr;
	if(max == 2) {
		// move the other twig to the parent branch.
		*n = *twig(n, !pos);
		region_recycle(t->region, oldt, max * sizeof(qp_node));
		t->count--;
		return;
	}
	// shrink twigs
	newt = region_alloc_array(t->region, max - 1, sizeof(qp_node));
	n->index &= ~(W1 << bit);
	n->ptr = newt;
	memcpy(newt, oldt, pos * sizeof(qp_node));
	memcpy(newt+pos, oldt+pos+1, (max-pos-1) * sizeof(qp_node));
	region_recycle(t->region, oldt, max * sizeof(qp_node));
	t->count--;
	return;
}

static inline qp_node *
last_leaf(qp_node *n) {
	while(isbranch(n)) {
		__builtin_prefetch(n->ptr);
		n = twig(n, twigmax(n) - 1);
	}
	return(n);
}

static inline qp_node *
first_leaf(qp_node *n) {
	while(isbranch(n))
		n = twig(n, 0);
	return(n);
}

/*
 * walk prev and next nodes down to their leaves,
 * and convert from nodes to values
 */
static struct prev_next
prev_next_leaves(struct prev_next pn) {
	qp_node *prev = pn.prev;
	qp_node *next = pn.next;
	if(prev != NULL) {
		prev = last_leaf(prev);
		pn.prev = (void *)prev->index;
	}
	if(next != NULL) {
		next = first_leaf(next);
		pn.next = (void *)next->index;
	}
	return(pn);
}

/*
 * update prev and next for this node
 */
static inline struct prev_next
prev_next_step(struct prev_next pn, qp_node *n, qp_weight pos, qp_weight max) {
	if(pos > 0)
		pn.prev = twig(n, pos - 1);
	if(pos < max - 1)
		pn.next = twig(n, pos + 1);
	return(pn);
}

/*
 * add
 */
struct prev_next
qp_add(struct qp_trie *t, const dname_type *dname, void *val) {
	qp_node *n = &t->root;
	qp_node newn, oldn;
	qp_node *oldt, *newt;
	qp_shift newb, oldb;
	qp_key newk, oldk;
	size_t newl = dname_to_key(dname, newk);
	size_t off;
	qp_shift bit;
	qp_weight pos, max;
	struct prev_next pn = { NULL, NULL };
	newn.ptr = (void *)(qp_word)dname; // cast away const, naughty
	newn.index = (qp_word)val;
	assert(!isbranch(&newn));
	// first leaf in an empty tree?
	if(t->count == 0) {
		*n = newn;
		t->count++;
		return(pn);
	}
	/*
	 * We need to keep searching down to a leaf even if our key is
	 * missing from this branch. It doesn't matter which twig we choose
	 * since the keys are all the same up to this node's offset. Note
	 * that if we simply use twigpos(n, bit) we may get an out-of-bounds
	 * access if our bit is greater than all the set bits in the node.
	 */
	while(isbranch(n)) {
		__builtin_prefetch(n->ptr);
		bit = twigbit(n, newk, newl);
		pos = hastwig(n, bit) ? twigpos(n, bit) : 0;
		n = twig(n, pos);
	}
	// do the keys differ, and if so, where?
	dname_to_key(n->ptr, oldk);
	for(off = 0; off <= newl; off++) {
		if(newk[off] != oldk[off])
			goto newkey;
	}
	// in NSD existing qp-trie entries are not updated in place
	assert(!"should not qp_add() an existing dname");
	return(pn);
newkey:
	newb = newk[off];
	oldb = oldk[off];
	// find where to insert a branch or grow an existing branch.
	n = &t->root;
	while(isbranch(n)) {
		__builtin_prefetch(n->ptr);
		if(off < keyoff(n))
			goto newbranch;
		if(off == keyoff(n))
			goto growbranch;
		bit = twigbit(n, newk, newl);
		assert(hastwig(n, bit));
		// keep track of adjacent nodes
		pos = twigpos(n, bit);
		max = twigmax(n);
		pn = prev_next_step(pn, n, pos, max);
		n = twig(n, pos);
	}
newbranch:
	newt = region_alloc_array(t->region, 2, sizeof(qp_node));
	oldn = *n; // save before overwriting.
	n->index = BRANCH_TAG
		 | (W1 << newb)
		 | (W1 << oldb)
		 | (off << SHIFT_OFFSET);
	n->ptr = newt;
	if(newb < oldb) {
		newt[0] = newn;
		pn.next = newt+1;
		newt[1] = oldn;
	} else {
		newt[0] = oldn;
		pn.prev = newt+0;
		newt[1] = newn;
	}
	t->count++;
	return(prev_next_leaves(pn));
growbranch:
	assert(!hastwig(n, newb));
	pos = twigpos(n, newb);
	max = twigmax(n);
	oldt = n->ptr;
	newt = region_alloc_array(t->region, max + 1, sizeof(qp_node));
	n->index |= W1 << newb;
	n->ptr = newt;
	memcpy(newt, oldt, pos * sizeof(qp_node));
	newt[pos] = newn;
	memcpy(newt+pos+1, oldt+pos, (max-pos) * sizeof(qp_node));
	region_recycle(t->region, oldt, max * sizeof(qp_node));
	t->count++;
	return(prev_next_leaves(prev_next_step(pn, n, pos, max + 1)));
}

/*
 * find_le
 */
int
qp_find_le(struct qp_trie *t, const dname_type *dname, void **pval) {
	qp_node *n = &t->root;
	qp_key key, found;
	size_t len = dname_to_key(dname, key);
	size_t off;
	qp_shift bit;
	qp_weight pos;
	qp_node *p;
	while(isbranch(n)) {
		__builtin_prefetch(n->ptr);
		bit = twigbit(n, key, len);
		if(!hastwig(n, bit))
			goto inexact;
		n = twig(n, twigpos(n, bit));
	}
	// fast check for exact match
	if(dname_equal(dname, n->ptr)) {
		*pval = (void *)n->index;
		return(1);
	}
	// empty tree
	if(n->ptr == NULL) {
		*pval = NULL;
		return(0);
	}
inexact:
	// slower path to find where the keys differ
	n = first_leaf(n);
	dname_to_key(n->ptr, found);
	for(off = 0; off <= len; off++) {
		if(key[off] != found[off])
			break;
	}
	// walk down again stopping at the correct place
	p = NULL;
	n = &t->root;
	while(isbranch(n)) {
		__builtin_prefetch(n->ptr);
		if(off < keyoff(n))
			goto prev;
		bit = twigbit(n, key, len);
		// keep track of previous node
		pos = twigpos(n, bit);
		if(pos > 0)
			p = twig(n, pos - 1);
		if(off == keyoff(n))
			goto here;
		assert(hastwig(n, bit));
		n = twig(n, pos);
	}
prev:
	if(key[off] > found[off]) {
		// everything in this subtree is before our search key
		n = last_leaf(n);
		*pval = (void *)n->index;
		return(0);
	}
	/* fall through */
here:
	if(p != NULL) {
		// the search key is just after the previous node
		n = last_leaf(p);
		*pval = (void *)n->index;
		return(0);
	} else {
		// the search key is before everything
		*pval = NULL;
		return(0);
	}
}
