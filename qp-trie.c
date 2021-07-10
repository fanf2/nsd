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

/* avoid depending on math.h or -lm */
static double sqrt(double n) {
	double m = n/2, x = 1, y = 0;
	while(x - y < -1E-6 || 1E-6 < x - y)
		y = x, x = x/2 + m/x;
	return(x);
}

/*
 * Percentiles would be more informative, but mean and standard
 * deviation are simple and enough to give us a rough idea of what is
 * happening.
 */
static void
stats_sample(struct qp_stats *stats, double sample) {
	stats->count += 1;
	stats->total += sample;
	stats->square += sample * sample;
}
static double
stats_mean(struct qp_stats *stats) {
	return(stats->total / stats->count);
}
static double
stats_sd(struct qp_stats *stats) {
	double mean = stats_mean(stats);
	return(sqrt(stats->square / stats->count - mean * mean));
}

static double
megabytes(uint32_t nodes) {
	return((double)(nodes * sizeof(qp_node)) / (1024 * 1024));
}

size_t
qp_print_memstats(FILE *fp, struct qp_trie *t) {
	struct qp_mem *m = &t->mem;
	size_t max = m->count;
	size_t garbage = 0;
	struct qp_stats stats = { 0, 0, 0 };
	for(uint32_t i = 0; i < max; i++) {
		uint32_t used = pageusage(t, i);
		bool active = m->page[i] != NULL;
		if(active)
		stats_sample(&stats, used);
		garbage += active && pageusage(t, i) < QP_MIN_USAGE;
	}
	fprintf(fp, "%.0f/%zu entries in page table (%.2f%%)\n",
		stats.count, max, stats.count * 100 / max);
	fprintf(fp, "%.0f nodes used (%.3f MiB / %.3f MiB)\n",
		stats.total, megabytes(stats.total),
		megabytes(stats.count * QP_PAGE_SIZE));
	double mean = stats_mean(&stats);
	fprintf(fp, "average usage %.1f +/- %.1f (%.2f%%)\n",
		mean, stats_sd(&stats), mean * 100 / QP_PAGE_SIZE);
	fprintf(fp, "%zu pages need compaction\n", garbage);
	fprintf(fp, "%.0f garbage collections\n",
		m->gc_time.count);
	fprintf(fp, "GC time %.1f +/- %.1f ms\n",
		stats_mean(&m->gc_time), stats_sd(&m->gc_time));
	fprintf(fp, "GC size %.1f +/- %.1f pages\n",
		stats_mean(&m->gc_space), stats_sd(&m->gc_space));
	return(stats.count * QP_PAGE_BYTES);
}

static qp_ref
qp_alloc_page(struct qp_trie *t, uint32_t page, qp_weight size) {
	qp_node *twigs = xalloc(QP_PAGE_BYTES);
	t->mem.page[page] = twigs;
	t->mem.usage[page].used = size;
	t->mem.here = page;
	return(QP_PAGE_SIZE * page);
}

static qp_ref
qp_alloc_slow(struct qp_trie *t, qp_weight size) {
	for(uint32_t p = t->mem.here; p < t->mem.count; p++)
		if(t->mem.page[p] == NULL)
			return(qp_alloc_page(t, p, size));
	for(uint32_t p = 0; p < t->mem.here; p++)
		if(t->mem.page[p] == NULL)
			return(qp_alloc_page(t, p, size));

	uint32_t last = t->mem.count;
	uint32_t count = last + last/2 + 1;
	qp_node **pages = xalloc(count * sizeof(*pages));
	struct qp_usage *usage = xalloc(count * sizeof(*usage));

	memcpy(pages, t->mem.page, last * sizeof(*pages));
	memcpy(usage, t->mem.usage, last * sizeof(*usage));
	memset(pages + last, 0, (count - last) * sizeof(*pages));
	memset(usage + last, 0, (count - last) * sizeof(*usage));
	free(t->mem.page);
	free(t->mem.usage);
	t->mem.page = pages;
	t->mem.usage = usage;
	t->mem.count = count;

	return(qp_alloc_page(t, last, size));
}

/*
 * Reset the allocator to the start of a fresh page
 */
static void
qp_alloc_reset(struct qp_trie *t) {
	qp_alloc_slow(t, 0);
}

static inline qp_ref
qp_alloc(struct qp_trie *t, qp_weight size) {
	uint32_t page = t->mem.here;
	uint32_t twig = t->mem.usage[page].used;
	if(QP_PAGE_SIZE > twig + size) {
		t->mem.usage[page].used += size;
		return(QP_PAGE_SIZE * page + twig);
	} else {
		return(qp_alloc_slow(t, size));
	}
}

/*
 * Make a note that these twigs are now garbage
 */
static inline void
landfill(struct qp_trie *t, qp_weight size, qp_ref base) {
	uint32_t page = refpage(base);
	t->mem.usage[page].free += size;
	t->mem.free += size;
}
static inline void
qp_garbage(struct qp_trie *t, qp_weight size, qp_ref base) {
	landfill(t, size, base);
	if(t->mem.free > QP_MAX_FREE)
		qp_compactify(t);
}

static void
compactify(struct qp_trie *t, qp_node *n) {
	qp_node twigs[SHIFT_OFFSET];
	qp_weight max = twigmax(n);
	size_t size = max * sizeof(*twigs);
	memcpy(twigs, twigbase(t, n), size);

	for(qp_weight i = 0; i < max; i++)
		if(isbranch(&twigs[i]))
			compactify(t, &twigs[i]);

	qp_ref oldr = twigref(n);
	if(pageusage(t, refpage(oldr)) >= QP_MIN_USAGE &&
	   memcmp(twigs, twigbase(t, n), size) == 0)
		return;

	qp_ref newr = qp_alloc(t, max);
	qp_node *newp = refptr(t, newr);
	memcpy(newp, twigs, size);
	*n = newnode(node64(n), newr);
	landfill(t, max, oldr);
}

void
qp_compactify(struct qp_trie *t) {
	double start = doubletime();
	qp_alloc_reset(t);
	if(isbranch(&t->root))
		compactify(t, &t->root);
	uint32_t pages = 0;
	for(uint32_t p = 0; p < t->mem.count; p++) {
		if(t->mem.page[p] == NULL)
			continue;
		if(pageusage(t, p) > 0)
			continue;
		free(t->mem.page[p]);
		t->mem.page[p] = NULL;
		t->mem.free -= t->mem.usage[p].free;
		memset(&t->mem.usage[p], 0, sizeof(t->mem.usage[p]));
		++pages;
	}
	double end = doubletime();
	stats_sample(&t->mem.gc_time, (end - start) * 1000);
	stats_sample(&t->mem.gc_space, pages);
}

struct qp_trie
qp_empty(void) {
	struct qp_trie t;
	memset(&t, 0, sizeof(t));
	qp_alloc_reset(&t);
	return t;
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
foreach(struct qp_trie *t, qp_node *n, void (*fn)(void *, void *), void *ctx) {
	if(isbranch(n)) {
		qp_weight pos, max;
		max = twigmax(n);
		for(pos = 0; pos < max; pos++)
			foreach(t, twig(t, n, pos), fn, ctx);
	} else {
		void *val = leafval(n);
		if(val != NULL)
			fn(val, ctx);
	}
}

void
qp_foreach(struct qp_trie *t, void (*fn)(void *, void *), void *ctx) {
	foreach(t, &t->root, fn, ctx);
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
		__builtin_prefetch(twigbase(t, n));
		bit = twigbit(n, key, len);
		if(!hastwig(n, bit))
			return(NULL);
		n = twig(t, n, twigpos(n, bit));
	}
	if(leafval(n) != NULL && dname_equal(dname, leafname(n)))
		return(leafval(n));
	else
		return(NULL);
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
	qp_ref oldr, newr;
	qp_node *oldp, *newp;
	qp_node *p = NULL;
	while(isbranch(n)) {
		__builtin_prefetch(twigbase(t, n));
		bit = twigbit(n, key, len);
		if(!hastwig(n, bit))
			return;
		p = n; n = twig(t, n, twigpos(n, bit));
	}
	if(!dname_equal(dname, leafname(n))) {
		return;
	}
	// tree becomes empty
	if(p == NULL) {
		memset(n, 0, sizeof(*n));
		t->count--;
		return;
	}
	// step back to parent node
	n = p; p = NULL;
	assert(bit != 0);
	pos = twigpos(n, bit);
	max = twigmax(n);
	oldr = twigref(n);
	if(max == 2) {
		// move the other twig to the parent branch.
		*n = *twig(t, n, !pos);
		t->count--;
		qp_garbage(t, max, oldr);
		return;
	}
	// shrink twigs
	newr = qp_alloc(t, max - 1);
	*n = newnode(node64(n) & ~(W1 << bit), newr);
	oldp = refptr(t, oldr);
	newp = refptr(t, newr);
	memcpy(newp, oldp, pos * sizeof(qp_node));
	memcpy(newp+pos, oldp+pos+1, (max-pos-1) * sizeof(qp_node));
	t->count--;
	qp_garbage(t, max, oldr);
	return;
}

static inline qp_node *
last_leaf(struct qp_trie *t, qp_node *n) {
	while(isbranch(n))
		n = twig(t, n, twigmax(n) - 1);
	return(n);
}

static inline qp_node *
first_leaf(struct qp_trie *t, qp_node *n) {
	while(isbranch(n))
		n = twig(t, n, 0);
	return(n);
}

/*
 * walk prev and next nodes down to their leaves,
 * and convert from nodes to values
 */
static struct prev_next
prev_next_leaves(struct prev_next pn, struct qp_trie *t) {
	qp_node *prev = pn.prev;
	qp_node *next = pn.next;
	if(prev != NULL) {
		prev = last_leaf(t, prev);
		pn.prev = leafval(prev);
	}
	if(next != NULL) {
		next = first_leaf(t, next);
		pn.next = leafval(next);
	}
	return(pn);
}

/*
 * update prev and next for this node
 */
static inline struct prev_next
prev_next_step(struct prev_next pn, struct qp_trie *t,
	       qp_node *n, qp_weight pos, qp_weight max)
{
	if(pos > 0)
		pn.prev = twig(t, n, pos - 1);
	if(pos < max - 1)
		pn.next = twig(t, n, pos + 1);
	return(pn);
}

/*
 * add
 */
struct prev_next
qp_add(struct qp_trie *t, void *val, const dname_type **ppdname) {
	const dname_type *dname = *ppdname;
	qp_node *n = &t->root;
	qp_ref oldr, newr;
	qp_node newn, oldn;
	qp_node *oldp, *newp;
	qp_shift newb, oldb;
	qp_key newk, oldk;
	size_t newl = dname_to_key(dname, newk);
	size_t off;
	qp_shift bit;
	qp_weight pos, max;
	struct prev_next pn = { NULL, NULL };
	newn = newleaf(val, ppdname);
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
		__builtin_prefetch(twigbase(t, n));
		bit = twigbit(n, newk, newl);
		pos = hastwig(n, bit) ? twigpos(n, bit) : 0;
		n = twig(t, n, pos);
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
	n = &t->root;
	while(isbranch(n)) {
		__builtin_prefetch(twigbase(t, n));
		if(off < keyoff(n))
			goto newbranch;
		if(off == keyoff(n))
			goto growbranch;
		bit = twigbit(n, newk, newl);
		assert(hastwig(n, bit));
		// keep track of adjacent nodes
		pos = twigpos(n, bit);
		max = twigmax(n);
		pn = prev_next_step(pn, t, n, pos, max);
		n = twig(t, n, pos);
	}
newbranch:
	newr = qp_alloc(t, 2);
	newp = refptr(t, newr);
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
	t->count++;
	return(prev_next_leaves(pn, t));
growbranch:
	assert(!hastwig(n, newb));
	pos = twigpos(n, newb);
	max = twigmax(n);
	oldr = twigref(n);
	newr = qp_alloc(t, max + 1);
	*n = newnode(node64(n) | (W1 << newb), newr);
	oldp = refptr(t, oldr);
	newp = refptr(t, newr);
	memcpy(newp, oldp, pos * sizeof(qp_node));
	newp[pos] = newn;
	memcpy(newp+pos+1, oldp+pos, (max-pos) * sizeof(qp_node));
	pn = prev_next_step(pn, t, n, pos, max + 1);
	pn = prev_next_leaves(pn, t);
	t->count++;
	qp_garbage(t, max, oldr);
	return(pn);
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
		__builtin_prefetch(twigbase(t, n));
		bit = twigbit(n, key, len);
		if(!hastwig(n, bit))
			goto inexact;
		n = twig(t, n, twigpos(n, bit));
	}
	// empty tree
	if(leafval(n) == NULL) {
		*pval = NULL;
		return(0);
	}
	// fast check for exact match
	if(dname_equal(dname, leafname(n))) {
		*pval = leafval(n);
		return(1);
	}
inexact:
	// slower path to find where the keys differ
	n = first_leaf(t, n);
	dname_to_key(leafname(n), found);
	for(off = 0; off <= len; off++) {
		if(key[off] != found[off])
			break;
	}
	// walk down again stopping at the correct place
	p = NULL;
	n = &t->root;
	while(isbranch(n)) {
		__builtin_prefetch(twigbase(t, n));
		if(off < keyoff(n))
			goto prev;
		bit = twigbit(n, key, len);
		// keep track of previous node
		pos = twigpos(n, bit);
		if(pos > 0)
			p = twig(t, n, pos - 1);
		if(off == keyoff(n))
			goto here;
		assert(hastwig(n, bit));
		n = twig(t, n, pos);
	}
prev:
	if(key[off] > found[off]) {
		// everything in this subtree is before our search key
		n = last_leaf(t, n);
		*pval = leafval(n);
		return(0);
	}
	/* fall through */
here:
	if(p != NULL) {
		// the search key is just after the previous node
		n = last_leaf(t, p);
		*pval = leafval(n);
		return(0);
	} else {
		// the search key is before everything
		*pval = NULL;
		return(0);
	}
}
