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

static double doubletime(void) {
	struct timespec t;
	get_time(&t);
	return((double)t.tv_sec + t.tv_nsec / 1000000000.0);
}

/*
 * Percentiles would be more informative, but mean and standard
 * deviation are simple and enough to give us a rough idea of what is
 * happening.
 */
static void
stats_sample(struct qp_stats *stats, double sample) {
	double delta = sample - stats->mean;
	stats->count += 1;
	stats->mean += delta / stats->count;
	stats->var += delta * (sample - stats->mean);
}

/* square root with Newton's method to avoid math.h or libm */
static double
stats_sd(struct qp_stats stats) {
	double n = stats.var / stats.count;
	double m = n / 2, y = n, x = m;
	while(n == n && y != x) y = x, x = x/2 + m/x;
	return(x); /* sqrt(n) */
}

size_t
qp_print_memstats(FILE *fp, struct qp *qp) {

#define print(name, val)						\
	fprintf(fp, name "%zu nodes %.1f MiB %.1f%%\n",			\
		(size_t)(val),						\
		(double)(val) * sizeof(qp_node) / (1048576.0),		\
		(double)(val) * 100.0 / qp->space)

	print("space   ", qp->space);
	print("active  ", qp->bump - qp->garbage);
	print("garbage ", qp->garbage);
	print("used    ", qp->bump);
	print("free    ", qp->space - qp->bump);

#undef print

	fprintf(fp, "%.0f garbage collections (total %.1f ms)\n",
		qp->gc_time.count, qp->gc_time.count * qp->gc_time.mean);
	fprintf(fp, "GC time %.1f +/- %.1f ms\n",
		qp->gc_time.mean, stats_sd(qp->gc_time));
	fprintf(fp, "GC size %.1f +/- %.1f KiB\n",
		qp->gc_space.mean, stats_sd(qp->gc_space));

	return(qp->space * sizeof(qp_node));
}

/*
 * Ensure that a certain amount of space is available.
 * Simplified Cheney copying garbage collector.
 */
static qp_node *
compactify(struct qp *qp, qp_size more) {
	double start = doubletime();
	qp_size space = QP_ALLOC_ROUND(qp->bump - qp->garbage + more);
	qp_node *base = xalloc(space * sizeof(*base));
	qp_ref bump = 0;
	base[bump++] = qp->base[0];

	for(qp_node *n = base; n < base + bump; n++) {
		if(isbranch(n)) {
			qp_weight max = twigmax(n);
			twigmove(base + bump, twig(qp, n, 0), max);
			*n = newnode(node64(n), bump);
			bump += max;
		}
	}

	double end = doubletime();
	stats_sample(&qp->gc_time, (end - start) * 1000);
	stats_sample(&qp->gc_space,
		     (double)qp->garbage * sizeof(qp_node) / 1024.0);

	qp->bump = bump;
	qp->space = space;
	qp->garbage = 0;
	return(base);
}

void
qp_compact(struct qp *qp, uint32_t space) {
	qp_node *base = compactify(qp, space);
	free(qp->base);
	qp->base = base;
}

/*
 * Reserve space for a new node
 */
static inline void
prealloc(struct qp *qp) {
	if(qp->bump + TWIGMAX >= qp->space)
		qp_compact(qp, QP_ALLOC_MORE(qp));
}

/*
 * A callback used by the region allocator.
 */
static void
cleanup(void *vp) {
	struct qp *qp = vp;
	free(qp->base);
}

static void
destroy(struct qp *qp, region_type *region) {
	cleanup(qp);
	region_recycle(region, qp, sizeof(*qp));
	region_remove_cleanup(region, cleanup, qp);
}

void
qp_destroy(struct qp_trie *t) {
	if(t->cow) destroy(t->cow, t->region);
	if(t->qp) destroy(t->qp, t->region);
	t->region = NULL;
	t->cow = NULL;
	t->qp = NULL;
}

void
qp_init(struct qp_trie *t, region_type *region) {
	struct qp *qp = region_alloc_zero(region, sizeof(*qp));
	region_add_cleanup(region, cleanup, qp);
	qp->space = QP_ALLOC_MORE(qp);
	qp->base = xalloc(qp->space * sizeof(*qp->base));
	qp->base[qp->bump++] = newnode(0, 0);
	t->region = region;
	t->cow = NULL;
	t->qp = qp;
}

void
qp_cow_start(struct qp_trie *t) {
	/* TODO: take cow write lock */
	region_type *region = t->region;
	t->cow = region_alloc(region, sizeof(*t->cow));
	memcpy(t->cow, t->qp, sizeof(*t->cow));
	t->cow->base = compactify(t->cow, QP_ALLOC_MORE(t->cow));
	region_add_cleanup(region, cleanup, t->cow);
}

void
qp_cow_finish(struct qp_trie *t) {
	struct qp *old = t->qp;

	/* TODO: take qp write lock */
	t->qp = t->cow;
	/* TODO: release qp write lock */

	free(old->base);
	region_recycle(t->region, old, sizeof(*old));
	region_remove_cleanup(t->region, cleanup, old);
	t->cow = NULL;
	/* TODO: release cow write lock */
}

uint32_t
qp_count(struct qp *qp) {
	return(qp->leaves);
}

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
static void
foreach(struct qp *qp, qp_node *n, void (*fn)(void *, void *), void *ctx) {
	if(isbranch(n)) {
		qp_weight pos, max;
		max = twigmax(n);
		for(pos = 0; pos < max; pos++)
			foreach(qp, twig(qp, n, pos), fn, ctx);
	} else {
		void *val = leafval(n);
		if(val != NULL)
			fn(val, ctx);
	}
}

void
qp_foreach(struct qp *qp, void (*fn)(void *, void *), void *ctx) {
	foreach(qp, qp->base, fn, ctx);
}

/*
 * get
 */
void *
qp_get(struct qp *qp, const dname_type *dname) {
	qp_node *n = qp->base;
	qp_key key;
	size_t len = dname_to_key(dname, key);
	qp_shift bit;
	while(isbranch(n)) {
		__builtin_prefetch(twig(qp, n, 0));
		bit = twigbit(n, key, len);
		if(!hastwig(n, bit))
			return(NULL);
		n = twig(qp, n, twigpos(n, bit));
	}
	if(dname_equal(dname, leafname(n)))
		return(leafval(n));
	else
		return(NULL);
}

/*
 * del
 */
void
qp_del(struct qp *qp, const dname_type *dname) {
	qp_node *n = qp->base;
	qp_key key;
	size_t len = dname_to_key(dname, key);
	qp_shift bit = 0;
	qp_weight pos, max;
	qp_ref ref;
	qp_node *twigs;
	qp_node *p = NULL;
	while(isbranch(n)) {
		__builtin_prefetch(twig(qp, n, 0));
		bit = twigbit(n, key, len);
		if(!hastwig(n, bit))
			return;
		p = n; n = twig(qp, n, twigpos(n, bit));
	}
	if(!dname_equal(dname, leafname(n))) {
		return;
	}
	// tree becomes empty
	if(p == NULL) {
		*n = newnode(0, 0);
		qp->leaves--;
		return;
	}
	// step back to parent node
	n = p; p = NULL;
	assert(bit != 0);
	pos = twigpos(n, bit);
	max = twigmax(n);
	ref = twigref(n);
	if(max == 2) {
		// move the other twig to the parent branch.
		*n = *twig(qp, n, !pos);
		qp->garbage += 2;
		qp->leaves--;
	} else {
		// shrink the twigs in place
		*n = newnode(node64(n) & ~(W1 << bit), twigref(n));
		twigs = twig(qp, n, 0);
		twigmove(twigs+pos, twigs+pos+1, max-pos-1);
		qp->garbage += 1;
		qp->leaves--;
	}
}

static inline qp_node *
last_leaf(struct qp *qp, qp_node *n) {
	while(isbranch(n))
		n = twig(qp, n, twigmax(n) - 1);
	return(n);
}

static inline qp_node *
first_leaf(struct qp *qp, qp_node *n) {
	while(isbranch(n))
		n = twig(qp, n, 0);
	return(n);
}

/*
 * walk prev and next nodes down to their leaves,
 * and convert from nodes to values
 */
static struct prev_next
prev_next_leaves(struct prev_next pn, struct qp *qp) {
	qp_node *prev = pn.prev;
	qp_node *next = pn.next;
	if(prev != NULL) {
		prev = last_leaf(qp, prev);
		pn.prev = leafval(prev);
	}
	if(next != NULL) {
		next = first_leaf(qp, next);
		pn.next = leafval(next);
	}
	return(pn);
}

/*
 * update prev and next for this node
 */
static inline struct prev_next
prev_next_step(struct prev_next pn, struct qp *qp,
	       qp_node *n, qp_weight pos, qp_weight max)
{
	if(pos > 0)
		pn.prev = twig(qp, n, pos - 1);
	if(pos < max - 1)
		pn.next = twig(qp, n, pos + 1);
	return(pn);
}

/*
 * add
 */
struct prev_next
qp_add(struct qp *qp, void *val, const dname_type **ppdname) {
	const dname_type *dname = *ppdname;
	qp_node *n;
	qp_ref oldr, newr;
	qp_node newn, oldn;
	qp_node *oldp, *newp;
	qp_shift newb, oldb;
	qp_key newk, oldk;
	size_t newl;
	size_t off;
	qp_shift bit;
	qp_weight pos, max;
	struct prev_next pn = { NULL, NULL };
	prealloc(qp);
	newn = newleaf(val, ppdname);
	// first leaf in an empty tree?
	if(qp->leaves == 0) {
		qp->bump = 0;
		qp->base[qp->bump++] = newn;
		qp->leaves++;
		return(pn);
	}
	/*
	 * We need to keep searching down to a leaf even if our key is
	 * missing from this branch. It doesn't matter which twig we choose
	 * since the keys are all the same up to this node's offset. Note
	 * that if we simply use twigpos(n, bit) we may get an out-of-bounds
	 * access if our bit is greater than all the set bits in the node.
	 */
	n = qp->base;
	newl = dname_to_key(dname, newk);
	while(isbranch(n)) {
		__builtin_prefetch(twig(qp, n, 0));
		bit = twigbit(n, newk, newl);
		pos = hastwig(n, bit) ? twigpos(n, bit) : 0;
		n = twig(qp, n, pos);
	}
	// do the keys differ, and if so, where?
	dname_to_key(leafname(n), oldk);
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
	n = qp->base;
	while(isbranch(n)) {
		__builtin_prefetch(twig(qp, n, 0));
		if(off < keyoff(n))
			goto newbranch;
		if(off == keyoff(n))
			goto growbranch;
		bit = twigbit(n, newk, newl);
		assert(hastwig(n, bit));
		// keep track of adjacent nodes
		pos = twigpos(n, bit);
		max = twigmax(n);
		pn = prev_next_step(pn, qp, n, pos, max);
		n = twig(qp, n, pos);
	}
newbranch:
	newr = qp->bump;
	newp = qp->base + newr;
	qp->bump += 2;
	oldn = *n; // save before overwriting.
	*n = newnode(BRANCH_TAG |
		   (W1 << newb) |
		   (W1 << oldb) |
		   (off << SHIFT_OFFSET),
		newr);
	if(newb < oldb) {
		newp[0] = newn;
		pn.next = newp+1;
		newp[1] = oldn;
	} else {
		newp[0] = oldn;
		pn.prev = newp+0;
		newp[1] = newn;
	}
	qp->leaves++;
	return(prev_next_leaves(pn, qp));
growbranch:
	assert(!hastwig(n, newb));
	pos = twigpos(n, newb);
	max = twigmax(n);
	oldr = twigref(n);
	newr = qp->bump;
	qp->bump += max + 1;
	oldp = qp->base + oldr;
	newp = qp->base + newr;
	*n = newnode(node64(n) | (W1 << newb), newr);
	twigmove(newp, oldp, pos);
	newp[pos] = newn;
	twigmove(newp+pos+1, oldp+pos, max-pos);
	pn = prev_next_step(pn, qp, n, pos, max + 1);
	pn = prev_next_leaves(pn, qp);
	qp->garbage += max;
	qp->leaves++;
	return(pn);
}

/*
 * find_le
 */
int
qp_find_le(struct qp *qp, const dname_type *dname, void **pval) {
	qp_node *n = qp->base;
	qp_key key, found;
	size_t len = dname_to_key(dname, key);
	size_t off;
	qp_shift bit;
	qp_weight pos;
	qp_node *p;
	while(isbranch(n)) {
		__builtin_prefetch(twig(qp, n, 0));
		bit = twigbit(n, key, len);
		if(!hastwig(n, bit))
			goto inexact;
		n = twig(qp, n, twigpos(n, bit));
	}
	// empty tree
	if(leafval(n) == NULL) {
		*pval = NULL;
		return(0);
	}
	// exact match
	if(dname_equal(dname, leafname(n))) {
		*pval = leafval(n);
		return(1);
	}
inexact:
	// slower path to find where the keys differ
	n = first_leaf(qp, n);
	dname_to_key(leafname(n), found);
	for(off = 0; off <= len; off++) {
		if(key[off] != found[off])
			break;
	}
	// walk down again stopping at the correct place
	p = NULL;
	n = qp->base;
	while(isbranch(n)) {
		__builtin_prefetch(twig(qp, n, 0));
		if(off < keyoff(n))
			goto prev;
		bit = twigbit(n, key, len);
		// keep track of previous node
		pos = twigpos(n, bit);
		if(pos > 0)
			p = twig(qp, n, pos - 1);
		if(off == keyoff(n))
			goto here;
		assert(hastwig(n, bit));
		n = twig(qp, n, pos);
	}
prev:
	if(key[off] > found[off]) {
		// everything in this subtree is before our search key
		n = last_leaf(qp, n);
		*pval = leafval(n);
		return(0);
	}
	/* fall through */
here:
	if(p != NULL) {
		// the search key is just after the previous node
		n = last_leaf(qp, p);
		*pval = leafval(n);
		return(0);
	} else {
		// the search key is before everything
		*pval = NULL;
		return(0);
	}
}
