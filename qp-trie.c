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

static double
megabytes(uint32_t nodes) {
	return((double)(nodes * sizeof(qp_node)) / (1024 * 1024));
}

size_t
qp_print_memstats(FILE *fp, struct qp *qp) {
	size_t pages = qp->pages;
	size_t total = 0;
	size_t garbage = 0;
	struct qp_stats stats = { 0, 0, 0 };

	for(qp_page p = 0; p < pages; p++) {
		qp_twig used = pageusage(qp, p);
		bool active = qp->base[p] != NULL;
		if(active)
			stats_sample(&stats, used);
		total += used;
		garbage += active && used < QP_MIN_USAGE;
	}

	fprintf(fp, "%.0f/%zu entries in page table (%.2f%%)\n",
		stats.count, pages, stats.count * 100 / pages);
	fprintf(fp, "%zu nodes used (%.3f MiB / %.3f MiB)\n",
		total, megabytes(total),
		megabytes(stats.count * QP_PAGE_SIZE));
	fprintf(fp, "average usage %.1f +/- %.1f (%.2f%%)\n",
		stats.mean, stats_sd(stats), stats.mean * 100 / QP_PAGE_SIZE);
	fprintf(fp, "%zu pages need GC\n", garbage);

	fprintf(fp, "%.0f garbage collections (total %.1f ms)\n",
		qp->gc_time.count, qp->gc_time.count * qp->gc_time.mean);
	fprintf(fp, "GC time %.1f +/- %.1f ms\n",
		qp->gc_time.mean, stats_sd(qp->gc_time));
	fprintf(fp, "GC size %.1f +/- %.1f pages\n",
		qp->gc_space.mean, stats_sd(qp->gc_space));
	fprintf(fp, "GC late %.1f +/- %.1f pages\n",
		qp->gc_later.mean, stats_sd(qp->gc_later));

	size_t elemsz = sizeof(*qp->base) + sizeof(*qp->usage);
	return(stats.count * QP_PAGE_BYTES + pages * elemsz);
}

/*
 * A mashup of calloc() and realloc() without any free().
 * See alloc_page() below for notes on xalloc().
 */
static void *
clone(void *oldp, size_t oldsz, size_t newsz, size_t elemsz) {
	assert((uint64_t)1 << 32 > (uint64_t)oldsz * elemsz);
	assert((uint64_t)1 << 32 > (uint64_t)newsz * elemsz);
	oldsz *= elemsz, newsz *= elemsz;
	unsigned char *newp = xalloc(newsz);
	size_t copysz = oldsz < newsz ? oldsz : newsz;
	size_t zerosz = newsz > copysz ? newsz - copysz : 0;
	if(copysz > 0) memcpy(newp, oldp, copysz);
	if(zerosz > 0) memset(newp + copysz, 0, zerosz);
	return(newp);
}

/*
 * Create a fresh page and allocate some twigs from it.
 *
 * I'm mostly avoiding the region allocator because I want to be clear
 * about the complete lifecycle of the memory managed by the qp-trie's
 * allocator, including shared copy-on-write pages. In particular, see
 * cleanup() below.
 */
static qp_ref
alloc_page(struct qp *qp, qp_page page, qp_weight size) {
	qp_node *twigs = xalloc(QP_PAGE_BYTES);
	qp->base[page] = twigs;
	qp->usage[page].used = size;
	qp->bump = page;
	return(QP_PAGE_SIZE * page);
}

/*
 * Find a place to put a fresh page in the page table.
 */
static qp_ref
alloc_slow(struct qp *qp, qp_weight size) {
	for(qp_page p = qp->bump; p < qp->pages; p++)
		if(qp->base[p] == NULL)
			return(alloc_page(qp, p, size));
	for(qp_page p = 0; p < qp->bump; p++)
		if(qp->base[p] == NULL)
			return(alloc_page(qp, p, size));

	qp_page last = qp->pages;
	qp_page pages = last + last/2 + 1;
	qp_node **base = qp->base;
	struct qp_usage *usage = qp->usage;
	qp->base = clone(base, last, pages, sizeof(*base));
	qp->usage = clone(usage, last, pages, sizeof(*usage));
	qp->pages = pages;
	free(base);
	free(usage);

	return(alloc_page(qp, last, size));
}

/*
 * Reset the allocator to the start of a fresh page
 */
static void
alloc_reset(struct qp *qp) {
	alloc_slow(qp, 0);
}

/*
 * Allocate some fresh twigs.
 */
static inline qp_ref
alloc(struct qp *qp, qp_weight size) {
	qp_page page = qp->bump;
	qp_twig twig = qp->usage[page].used;
	if(QP_PAGE_SIZE >= twig + size) {
		qp->usage[page].used += size;
		return(QP_PAGE_SIZE * page + twig);
	} else {
		return(alloc_slow(qp, size));
	}
}

/*
 * Discard some twigs without trying to clean up.
 */
static inline void
landfill(struct qp *qp, qp_ref twigs, qp_weight size) {
	qp_page page = refpage(twigs);
	qp->usage[page].free += size;
	qp->garbage += size;
}

/*
 * Discard some twigs and clean up if necessary.
 */
static inline void
garbage(struct qp *qp, qp_ref twigs, qp_weight size) {
	landfill(qp, twigs, size);
	if(qp->garbage > QP_MAX_GARBAGE)
		qp_compact(qp);
}

/*
 * Move some twigs to a new page. The twigs pointer is normally
 * twigbase(qp, n) except during garbage collection when the twigs
 * are moved via a temporary copy.
 */
static inline void
evacuate(struct qp *qp, qp_node *n, qp_node *twigs) {
	qp_weight max = twigmax(n);
	qp_ref ref = alloc(qp, max);
	landfill(qp, twigref(n), max);
	twigmove(refptr(qp, ref), twigs, max);
	*n = newnode(node64(n), ref);
}

/*
 * The copying part of our copying garbage collector.
 */
static void
defrag(struct qp *qp, qp_node *n) {
	qp_node twigs[SHIFT_OFFSET];
	qp_weight max = twigmax(n);
	twigmove(twigs, twigbase(qp, n), max);

	for(qp_weight i = 0; i < max; i++)
		if(isbranch(&twigs[i]))
			defrag(qp, &twigs[i]);

	if(pageusage(qp, refpage(twigref(n))) < QP_MIN_USAGE
	   || twigcmp(twigs, twigbase(qp, n), max) != 0)
		evacuate(qp, n, twigs);
}

/*
 * The garbage collector can either free unused pages immediately
 * (which it does for on-demand collections) or when completing a COW
 * transaction it can put them on a list to be dealt with after the
 * old/new switch-over. The current allocation page is in use even if
 * it is empty.
 */
static void
recycle(struct qp *qp, qp_node **later) {
	double start = doubletime();
	qp_page pages = 0;

	alloc_reset(qp);
	if(isbranch(&qp->root))
		defrag(qp, &qp->root);

	for(qp_page p = 0; p < qp->pages; p++) {
		if(p == qp->bump)
			continue;
		if(pageusage(qp, p) > 0)
			continue;
		if(later != NULL)
			later[p] = qp->base[p];
		else
			free(qp->base[p]);
		qp->base[p] = NULL;
		qp->garbage -= qp->usage[p].free;
		memset(&qp->usage[p], 0, sizeof(qp->usage[p]));
		++pages;
	}

	double end = doubletime();
	stats_sample(&qp->gc_time, (end - start) * 1000);
	stats_sample(&qp->gc_space, pages);
}

/*
 * GC right now.
 */
void
qp_compact(struct qp *qp) {
	recycle(qp, NULL);
}

/*
 * A callback used by the region allocator.
 * See alloc_page() above for a rationale.
 */
static void
cleanup(void *vp) {
	struct qp *qp = vp;
	for(qp_page p = 0; p < qp->pages; p++)
		if(qp->usage[p].keep == 0)
			free(qp->base[p]);
	free(qp->base);
	free(qp->usage);
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
	alloc_reset(qp);
	region_add_cleanup(region, cleanup, qp);
	t->region = region;
	t->cow = NULL;
	t->qp = qp;
}

void
qp_cow_start(struct qp_trie *t) {
	/* TODO: take cow write lock */

	region_type *region = t->region;
	qp_page pages = t->qp->pages;
	struct qp *old = t->qp;
	struct qp *new = region_alloc(region, sizeof(*new));

	memcpy(new, old, sizeof(*new));
	new->base = clone(old->base, pages, pages, sizeof(*old->base));
	new->usage = clone(old->usage, pages, pages, sizeof(*old->usage));

	for(qp_page p = 0; p < pages; p++)
		new->usage[p].keep = new->usage[p].used;

	alloc_reset(new);
	region_add_cleanup(region, cleanup, new);
	t->cow = new;
}

void
qp_cow_finish(struct qp_trie *t) {
	region_type *region = t->region;
	struct qp *old = t->qp;
	struct qp *new = t->cow;
	qp_page pages = new->pages;

	for(qp_page p = 0; p < pages; p++)
		new->usage[p].keep = 0;

	qp_node **later = clone(NULL, 0, pages, sizeof(*later));
	recycle(new, later);

	/* TODO: take qp write lock */
	t->qp = new;
	/* TODO: release qp write lock */

	qp_page late = 0;
	for(qp_page p = 0; p < pages; p++) {
		if(later[p] != NULL) {
			free(later[p]);
			++late;
		}
	}
	stats_sample(&old->gc_later, late);

	free(later);
	free(old->base);
	free(old->usage);
	region_recycle(region, old, sizeof(*old));
	region_remove_cleanup(region, cleanup, old);
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
	foreach(qp, &qp->root, fn, ctx);
}

/*
 * get
 */
void *
qp_get(struct qp *qp, const dname_type *dname) {
	qp_node *n = &qp->root;
	qp_key key;
	size_t len = dname_to_key(dname, key);
	qp_shift bit;
	while(isbranch(n)) {
		__builtin_prefetch(twigbase(qp, n));
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
	qp_node *n = &qp->root;
	qp_key key;
	size_t len = dname_to_key(dname, key);
	qp_shift bit = 0;
	qp_weight pos, max;
	qp_node *twigs;
	qp_node *p = NULL;
	while(isbranch(n)) {
		bit = twigbit(n, key, len);
		if(!hastwig(n, bit))
			return;
		evacuate(qp, n, twigbase(qp, n));
		p = n; n = twig(qp, n, twigpos(n, bit));
	}
	if(!dname_equal(dname, leafname(n))) {
		return;
	}
	// tree becomes empty
	if(p == NULL) {
		memset(n, 0, sizeof(*n));
		qp->leaves--;
		return;
	}
	// step back to parent node
	n = p; p = NULL;
	assert(bit != 0);
	pos = twigpos(n, bit);
	max = twigmax(n);
	if(max == 2) {
		// move the other twig to the parent branch.
		*n = *twig(qp, n, !pos);
		qp->leaves--;
		garbage(qp, twigref(n), 2);
	} else {
		// shrink the twigs we just evacuated
		*n = newnode(node64(n) & ~(W1 << bit), twigref(n));
		twigs = twigbase(qp, n);
		twigmove(twigs+pos, twigs+pos+1, max-pos-1);
		qp->leaves--;
		garbage(qp, twigref(n), 1);
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
	qp_node *n = &qp->root;
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
	if(qp->leaves == 0) {
		*n = newn;
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
	while(isbranch(n)) {
		__builtin_prefetch(twigbase(qp, n));
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
	n = &qp->root;
	while(isbranch(n)) {
		if(off < keyoff(n))
			goto newbranch;
		if(off == keyoff(n))
			goto growbranch;
		evacuate(qp, n, twigbase(qp, n));
		bit = twigbit(n, newk, newl);
		assert(hastwig(n, bit));
		// keep track of adjacent nodes
		pos = twigpos(n, bit);
		max = twigmax(n);
		pn = prev_next_step(pn, qp, n, pos, max);
		n = twig(qp, n, pos);
	}
newbranch:
	newr = alloc(qp, 2);
	newp = refptr(qp, newr);
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
	newr = alloc(qp, max + 1);
	*n = newnode(node64(n) | (W1 << newb), newr);
	oldp = refptr(qp, oldr);
	newp = refptr(qp, newr);
	memcpy(newp, oldp, pos * sizeof(qp_node));
	newp[pos] = newn;
	memcpy(newp+pos+1, oldp+pos, (max-pos) * sizeof(qp_node));
	pn = prev_next_step(pn, qp, n, pos, max + 1);
	pn = prev_next_leaves(pn, qp);
	qp->leaves++;
	garbage(qp, oldr, max);
	return(pn);
}

/*
 * find_le
 */
int
qp_find_le(struct qp *qp, const dname_type *dname, void **pval) {
	qp_node *n = &qp->root;
	qp_key key, found;
	size_t len = dname_to_key(dname, key);
	size_t off;
	qp_shift bit;
	qp_weight pos;
	qp_node *p;
	while(isbranch(n)) {
		__builtin_prefetch(twigbase(qp, n));
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
	n = &qp->root;
	while(isbranch(n)) {
		__builtin_prefetch(twigbase(qp, n));
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
