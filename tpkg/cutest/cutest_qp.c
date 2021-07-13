/*
 * test qp-trie.c
 *
 * Written by Tony Finch <dot@dotat.at>
 * You may do anything with this. It has no warranty.
 * <http://creativecommons.org/publicdomain/zero/1.0/>
 */

#include "config.h"

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include "tpkg/cutest/cutest.h"
#include "region-allocator.h"
#include "dname.h"
#include "util.h"
#include "qp-trie.h"
#include "qp-bits.h"

#define CuAssertPtrEq CuAssertPtrEquals_Msg

static int v = 0; /* verbosity */
static int fast = 0; /* avoid being quadratic */
static CuTest* tc = NULL;

/*
 * Test elements
 */
struct elem {
	/* this element's key */
	const dname_type *dname;
	/* this element's neighbours */
	struct elem *prev, *next;
};

struct check_ctx {
	size_t count;
	struct elem *prev, *next;
};

/*
 * walk a tree and check it is consistent
 */
static void
qp_check_node(struct qp *qp, qp_node *n, struct check_ctx *ctx, size_t min_off) {
	if(isbranch(n)) {
		qp_weight max, i;
		size_t off;
		off = keyoff(n);
		CuAssert(tc, "check_node increasing off",
			 min_off <= off);
		max = twigmax(n);
		CuAssert(tc, "check_node min twigs",
			 max >= 2);
		CuAssert(tc, "check_node max twigs",
			 max <= (SHIFT_OFFSET - SHIFT_NOBYTE));
		for(i = 0; i < max; i++) {
			qp_check_node(qp, twig(qp, n, i), ctx, off + 1);
		}
	} else {
		struct elem *e = leafval(n);
		CuAssert(tc, "check_node val non-NULL",
			 e != NULL);
		CuAssert(tc, "check_node key val match",
			 e->dname == leafname(n));
		if(ctx->count == 0) {
			CuAssertPtrEq(tc, "check_node first elem prev",
				      e->prev, NULL);
			CuAssertPtrEq(tc, "check_node first elem",
				      ctx->next, NULL);
		} else {
			CuAssertPtrNotNullMsg(tc, "check_node prev elem",
				      ctx->prev);
			CuAssertPtrNotNullMsg(tc, "check_node prev elem link",
				      e->prev);
			CuAssertPtrEq(tc, "check_node this elem prev link",
				      e->prev, ctx->prev);
			CuAssertPtrEq(tc, "check_node expected this elem",
				      ctx->next, e);
			CuAssert(tc, "check_node prev elem before this",
				 dname_compare(e->prev->dname, e->dname) < 0);
		}
		if(e->next != NULL) {
			CuAssert(tc, "check_node this elem before next",
				 dname_compare(e->dname, e->next->dname) < 0);
		}
		ctx->prev = e;
		ctx->next = e->next;
		ctx->count++;
	}
}

static void
qp_check(struct qp *qp) {
	struct check_ctx ctx = { 0, NULL, NULL };
	if(fast) return;
	if(qp->leaves == 0) {
		CuAssert(tc, "check empty node",
			 node64(&qp->root) == 0 &&
			 node32(&qp->root) == 0);
	} else {
		qp_check_node(qp, &qp->root, &ctx, 0);
		CuAssert(tc, "check count", ctx.count == qp->leaves);
		CuAssertPtrEq(tc, "check last item",
			      ctx.next, NULL);
	}
}

/*
 * debug messages
 */
static void
print_bit(qp_shift bit) {
	unsigned min = 255, max = 0;
	if(bit == SHIFT_NOBYTE) {
		printf("NO");
		return;
	}
	for(unsigned byte = 0; byte < 256; byte++) {
		if(byte_to_bits[byte] % 256 == bit) {
			if(min > byte) min = byte;
			if(max < byte) max = byte;
		}
	}
	if(min == max)
		printf("%c", min);
	else if('A' <= min && min <= 'Z')
		printf("%c", max);
	else
		printf("\\%03d-\\%03d", min, max);
	printf(" or esc %02x", bit);
}

static void
print_bitmap(qp_node *n) {
	qp_shift bit;
	char sep = '(';
	for(bit = SHIFT_NOBYTE; bit < SHIFT_OFFSET; bit++) {
		if(!hastwig(n, bit))
			continue;
		putchar(sep);
		print_bit(bit);
		sep = ',';
	}
	printf(")\n");
}

void
qp_dump(struct qp *qp, qp_node *n, int d) {
	qp_shift bit;
	int dd;
	if(isbranch(n)) {
		printf("qp_dump%*s branch %p %zu ", d, "", n, keyoff(n));
		print_bitmap(n);
		dd = (int)keyoff(n) * 2 + 2;
		assert(dd > d);
		for(bit = SHIFT_NOBYTE; bit < SHIFT_OFFSET; bit++) {
			if(hastwig(n, bit)) {
				printf("qp_dump%*s twig ", d, "");
				print_bit(bit);
				putchar('\n');
				qp_dump(qp, twig(qp, n, twigpos(n, bit)), dd);
			}
		}
	} else {
		struct elem *e = leafval(n);
		printf("qp_dump%*s leaf %p\n", d, "", n);
		printf("qp_dump%*s leaf key %p %s\n", d, "",
		       leafname(n), leafname(n) == NULL ? ""
		       : dname_to_string(leafname(n), NULL));
		printf("qp_dump%*s leaf val %p << %p >> %p\n", d, "",
		       e ? e->prev : NULL, e, e ? e->next : NULL);
	}
}

/*
 * generate a random domain name
 */
static const dname_type *
random_dname(region_type *region)
{
	uint8_t buf[256];
	int labels, lab, len, i, off;
	const dname_type *dname;

	off = 0;
	labels = random_generate(5);
	for(lab = 0; lab < labels; lab++) {
		len = random_generate(3) + 1;
		CuAssert(tc, "random label fits", off + len + 1 < 255);
		buf[off++] = (uint8_t)len;
		for(i = 0; i < len; i++) {
			//buf[off++] = (uint8_t)('a' + random_generate(26));
			buf[off++] = (uint8_t)random_generate(256);
		}
	}
	buf[off++] = 0;

	dname = dname_make(region, buf, 1);
	CuAssert(tc, "random dname parsed ok", dname != NULL);

	return(dname);
}

static const dname_type *
wildcard_dname(region_type *region)
{
	const dname_type *dname;

	dname = dname_make(region, (uint8_t*)"\001*", 1);
	CuAssert(tc, "wildcard dname parsed ok", dname != NULL);

	return(dname);
}

static void
recycle_dname(region_type *region, const dname_type *dname) {
	region_recycle(region, (void*)(uintptr_t)dname,
		       dname_total_size(dname));
}

static struct elem *
add_elem(region_type *region, struct qp *qp, const dname_type *dname) {
	struct elem *e;
	struct prev_next pn;

	e = region_alloc(region, sizeof(*e));
	e->dname = dname;

	if(v) printf("add_elem %p %s\n", e, dname_to_string(dname, NULL));

	pn = qp_add(qp, e, &e->dname);
	e->prev = pn.prev;
	e->next = pn.next;
	CuAssertPtrEq(tc, "add_elem elem in tree",
		      qp_get(qp, e->dname), e);

	if(e->prev != NULL) {
		CuAssertPtrEq(tc, "add_elem prev consistent",
			      e->prev->next, e->next);
		e->prev->next = e;
	}
	if(e->next != NULL) {
		CuAssertPtrEq(tc, "add_elem prev consistent",
			      e->next->prev, e->prev);
		e->next->prev = e;
	}

	if(v) qp_dump(qp, &qp->root, 0);
	qp_check(qp);

	return(e);
}

static struct elem *
add_random_elem(region_type *region, struct qp *qp) {
	const dname_type *dname;

	for(;;) {
		dname = random_dname(region);
		if(qp_get(qp, dname) == NULL)
			break;
		recycle_dname(region, dname);
	}
	return(add_elem(region, qp, dname));
}

static void
del_elem(region_type *region, struct qp *qp, struct elem *e) {

	if(v) printf("del_elem %p %s\n", e, dname_to_string(e->dname, NULL));

	CuAssertPtrEq(tc, "del_elem elem in tree",
		      qp_get(qp, e->dname), e);
	qp_del(qp, e->dname);
	CuAssertPtrEq(tc, "del_elem elem not in tree",
		      qp_get(qp, e->dname), NULL);

	if(e->prev) e->prev->next = e->next;
	if(e->next) e->next->prev = e->prev;
	recycle_dname(region, e->dname);
	region_recycle(region, e, sizeof(*e));

	if(v) qp_dump(qp, &qp->root, 0);
	qp_check(qp);
}

static void
elem_looper(void *val, void *ctx) {
	struct elem *e = val;
	struct elem **it = ctx;

	if(v) printf("elem_loop %p %s\n", e, dname_to_string(e->dname, NULL));

	CuAssertPtrEq(tc, "elem_looper expected elem",
		      e, *it);
	*it = e->next;
}

static struct elem *
random_elem(struct elem *e) {
	while(e != NULL) {
		if(random_generate(3) == 0)
			return(e);
		e = e->next;
	}
	return(NULL);
}

static void
cutest_qp(CuTest *ttc)
{
	struct region *region = region_create(xalloc, free);
	struct qp_trie t;
	struct elem *first, *e;
	const dname_type *dname;
	void *val;
	int i;

	tc = ttc;

	qp_init(&t, region);

	first = NULL;
	for(i = 0; i < 10000; i++) {
		switch(random_generate(5)) {
		case(0):
			e = add_random_elem(region, t.qp);
			if(e->prev == NULL && first != NULL) {
				CuAssertPtrEq(tc, "new elem before first",
					      first->prev, e);
				CuAssertPtrEq(tc, "first after new elem",
					      e->next, first);
			}
			if(e->prev == NULL)
				first = e;
			continue;
		case(1):
			e = random_elem(first);
			if(e != NULL) {
				if(e == first)
					first = e->next;
				del_elem(region, t.qp, e);
			}
			continue;
		case(2):
			e = first;
			qp_foreach(t.qp, elem_looper, &e);
			CuAssertPtrEq(tc, "elem_looper expected last",
				      e, NULL);
			continue;
		case(3):
			qp_compact(t.qp);
			qp_check(t.qp);
			continue;
		case(4):
			if(random_generate(5) == 0)
				dname = wildcard_dname(region);
			else
				dname = random_dname(region);
			if(v) {
				printf("qp_find_le search %s\n",
				       dname_to_string(dname, NULL));
			}
			if(qp_find_le(t.qp, dname, &val)) {
				e = val;
				CuAssert(tc, "qp_find_le exact",
					 dname_compare(dname, e->dname) == 0);
				if(v) {
					printf("qp_find_le exact %s\n",
					       dname_to_string(e->dname, NULL));
				}
			} else if(val != NULL) {
				e = val;
				if(v) {
					printf("qp_find_le found %s\n",
					       dname_to_string(e->dname, NULL));
					printf("qp_find_le inexact %d\n",
					       dname_compare(dname, e->dname));
				}
				CuAssert(tc, "qp_find_le inexact",
					 dname_compare(dname, e->dname) > 0);
			} else if(first != NULL) {
				if(v) {
					printf("qp_find_le first %s\n",
					       dname_to_string(first->dname, NULL));
					printf("qp_find_le inexact %d\n",
					       dname_compare(dname, first->dname));
				}
				CuAssert(tc, "qp_find_le first",
					 dname_compare(dname, first->dname) < 0);
			}
			recycle_dname(region, dname);
			continue;
		default:
			assert(0);
		}
	}

	while(first != NULL) {
		e = first;
		first = e->next;
		del_elem(region, t.qp, e);
	}
	qp_destroy(&t);
	region_destroy(region);
}

CuSuite *
reg_cutest_qp(void)
{
        CuSuite* suite = CuSuiteNew();

	SUITE_ADD_TEST(suite, cutest_qp);
	return suite;
}
