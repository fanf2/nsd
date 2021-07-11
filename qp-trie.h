/*
 * qp-trie - a DNS-specific quelques-bits popcount trie for NSD
 *
 * Written by Tony Finch <dot@dotat.at>
 * See LICENSE for the license.
 */
#ifndef QP_TRIE_H
#define QP_TRIE_H

/*
 * A qp-trie node can be a leaf or a branch. It consists of three
 * 32-bit words into which the components are packed. They are
 * used as a 64-bit word and a 32-bit word, but they are not
 * declared like that to avoid unwanted padding.
 *
 * A branch contains:
 *
 * - The bottom bit is a non-zero tag.
 *
 * - A 47-bit bitmap that marks which twigs are present.
 *
 * - The 9-bit offset of the byte in the key which is used to find
 *   the child twig.
 *
 * - The 32-bit node reference of the twigs, which are a packed
 *   sparse vector of child nodes.
 *
 * A leaf contains:
 *
 * - A word-aligned pointer to the value, which can be up to 64 bits.
 *
 * - The offsetof() the dname pointer within the value, which must
 *   be less than 32 bits.
 */
typedef struct qp_node {
	uint32_t word[3];
} qp_node;

/*
 * Information used by the allocator and garbage collector.
 *
 * `count` is the number of elements in the page and stats arrays.
 *
 * `here` is the page currently being used for allocation.
 *
 * `free` is the sum of all the per-page free counters.
 *
 * `gc_time` and `gc_space` summarize garbage collection performance.
 *
 * `page` is an array of pointers to pages.
 *
 * `usage` is an array containing information about each page.
 *
 * They are separate arrays because the usage counters are not
 * used in the fast path.
 */
struct qp_stats {
	double count, total, square;
};
struct qp_usage {
	uint32_t used, free;
};
struct qp_mem {
	uint32_t count, here, free;
	qp_node **page;
	struct qp_usage *usage;
	struct qp_stats gc_time, gc_space;
};

/*
 * A qp-trie
 */
struct qp_trie {
	/** count of number of elements */
	size_t count;
	/** the root node */
	qp_node root;
	/** memory */
	struct qp_mem mem;
};

/*
 * Initialize a qp_trie
 */
struct qp_trie qp_empty(void);

/*
 * Neighbours of a newly added item
 */
struct prev_next {
	void *prev, *next;
};

/*
 * Add an item to a qp_trie, and return its neighbours
 */
struct prev_next qp_add(struct qp_trie *t, void *val, const dname_type **dp);

/*
 * Delete an entry from a qp_trie
 */
void qp_del(struct qp_trie *t, const dname_type *dname);

/*
 * Find an exact match in a qp_trie
 *
 * Returns the associated value, or NULL
 */
void *qp_get(struct qp_trie *t, const dname_type *dname);

/*
 * Find dname or its nearest predecessor; return true if we found an exact match
 */
int qp_find_le(struct qp_trie *t, const dname_type *dname, void **val);

/*
 * Invoke a function for each item in the tree
 */
void qp_foreach(struct qp_trie *t, void (*fn)(void *val, void *ctx), void *ctx);

/*
 * Garbage collector.
 */
void qp_compactify(struct qp_trie *t);

/*
 * Print memory statistics, and return the total used.
 */
size_t qp_print_memstats(FILE *fp, struct qp_trie *t);

#endif /* QP_TRIE_H */

/* And now for an essay about...

WHAT IS A TRIE?

A trie is another name for a radix tree, short for reTRIEval. In a
trie, keys are divided into digits depending on some radix e.g.
base 2 for binary tries, base 256 for byte-indexed tries. When
searching the trie, successive digits in the key, from most to
least significant, are used to select branches from successive
nodes in the trie, roughly like:

	for(off = 0; isbranch(node); off++)
		node = node->branch[key[off]];

All of the keys in a subtrie have identical prefixes. Tries do not
need to store keys since they are implicit in the structure.

A patricia trie is a binary trie which omits nodes that have only one
child. DJB calls his tightly space-optimized version a "crit-bit tree".
https://cr.yp.to/critbit.html https://github.com/agl/critbit/

Nodes are annotated with the offset of the bit that is used to
select the branch; offsets always increase as you go deeper into
the trie. Each leaf refers to a copy of its key so that when you
find a leaf you can verify that the untested bits match.

PACKED SPARSE VECTORS WITH POPCOUNT

The popcount() instruction counts the number of bits that are set
in a word. It's also known as the Hamming weight; Knuth calls it
"sideways add". https://en.wikipedia.org/wiki/popcount

You can use popcount() to implement a sparse vector of length N
containing M <= N members using bitmap of length N and a packed
vector of M elements. A member b is present in the vector if bit b
is set, so M == popcount(bitmap). The index of member b in the
packed vector is the popcount of the bits preceding b.

	mask = 1 << b;
	if(bitmap & mask)
		member = vector[popcount(bitmap & mask-1)]

See "Hacker's Delight" by Hank Warren, section 5-1 "Counting 1
bits", subsection "applications". http://www.hackersdelight.org

POPCOUNT FOR TRIE NODES

Phil Bagwell's hashed array-mapped tries (HAMT) use popcount for
compact trie nodes. String keys are hashed, and the hash is used
as the index to the trie, with radix 2^32 or 2^64.
http://infoscience.epfl.ch/record/64394/files/triesearches.pdf
http://infoscience.epfl.ch/record/64398/files/idealhashtrees.pdf

The performance of of a trie depends on its depth. A larger radix
correspondingly reduces the depth, so it should be faster. The
downside is usually much greater memory overhead. Node vectors are
often sparsly populated, so packing them can greatly reduce the
overhead. The HAMT also relies on hashing, which keeps keys dense,
at the cost of storing keys out of order.

QP TRIE

A qp-trie is a mash-up of Bagwell's HAMT with DJB's crit-bit tree.

A general-purpose qp-trie is a radix 16 or 32 patricia trie, so it
uses its keys 4 or 5 bits at a time. It uses 16-wide or 32-wide
bitmap to mark which children are present and popcount to index
them, like a narrower Bagwell HAMT. Each node contains the offset
of the 4-bit or 5-bit nybble that identifies the node's child, as
in a crit-bit tree.

A qp-trie is faster than a crit-bit tree and uses less memory,
because it requires fewer nodes and popcount packs them very
efficiently. Like a crit-bit tree but unlike a HAMT, a qp-trie
stores keys in lexicographic order.

The fan-out of a qp-trie is limited by the size of a word, minus
space for the nybble offset; 16 or 32 works well, and 32 is
slightly faster. But radix 64 requires an extra word per node, and
the extra memory overhead makes it slower as well as bulkier.

As in a HAMT, a qp-trie node is a pair of words, which are used as
key and value pointers in leaf nodes, and index word and pointer
in branch nodes. The index word contains the popcount bitmap and
the offset into the key, as well as a leaf/branch tag bit. The
pointer refers to the branch node's "twigs", which is what we call
the packed sparse vector of child nodes.

DNS QP TRIE

This code implements a DNS-specific variant of a qp-trie, tuned
for keys that use the usual hostname alphabet of
(case-insensitive) letters, digits, hyphen, plus underscore (which
is often used for non-hostname purposes), and finally the label
separator (which is written as '.' in presentation-format domain
names, and is the label length in wire format). These are the 39
common characters.

When a key only uses these characters, a DNS qp-trie has the same
depth as a byte-at-a-time radix 256 trie. But it doesn't use any
more memory than a qp-trie, because a 39-wide bitmap still fits in
a word.

To support keys that use unusual characters, a DNS qp-trie can use 2
nodes per byte, vaguely like a 4-bit qp-trie, except that the upper
node acts as an escape character, and the lower node identifies the
specific character that was escaped.

The index word also contains an offset into the key, so the size
of this offset field is limited by the space left over by the
bitmap, and the size of the offset field limits the maximum length
of a key. Domain names have a maximum length of 255 bytes, and we
have over 10 bits remaining, so the large DNS qp-trie bitmap is
not a problem.

ALLOCATION AND GARBAGE COLLECTION

This qp-trie implementation has its own allocator and garbage
collector, to provide two advantages: smaller tree nodes, and
concurrent update transactions.

Instead of using a native (64-bit) twigs pointer in a branch node, we
use a 32-bit reference. This contains a page number and an offset to
the twigs inside that page. A page number is an index into the
allocator's page table. This reduces the size of a node from 16 bytes
to 12 bytes. In a leaf node, instead of a direct pointer to the key
(domain name) we require that the value contains the name, so we can
get hold of it indirectly.

To allow queries to continue while an update is in progress, the tree
must be immutable, and modifications must be copy-on-write. The nodes
that were copied will become garbage, but not until the transaction
has committed and the query threads have switched over to the new
tree. Before committing, the new tree can be compacted to reduce
fragmentation; after committing, all the garbage can be recycled.

FITTING A QP TRIE INTO NSD

There are a couple of ways in which the qp-trie design doesn't fit
perfectly snugly into the rest of NSD.

NSD assumes that it can walk back and forth through its domain
names using just pointers to the domain objects (the value objects
from a qp-trie point of view). There's a space/time trade-off when
fitting a qp-trie in to this situation: we can use an extra word
per domain to point to the root of the qp-trie, which can then be
used for ordered lookups; or we can use two words to thread a
doubly-linked list through them all. I'm choosing to do the
latter.

A rough estimate of qp-trie memory usage is 16 - 20 bytes per object:
12 bytes for each leaf node and a few bytes per object shared between
the interior branch nodes. (It varies between about 8 and 8 bytes per
object depending on the set of keys.) In NSD we are adding prev+next
pointers to each domain object as well. So we expect the qp-trie to
use about 4 words per domain.

By comparison, NSD's radtree structure uses 5 words per domain plus
overhead for internal branching, typically 200 - 300 bytes per object.
The rbtree structure normally uses 4 words per domain.

POSSIBLE IMPROVEMENTS

In NSD we have a tree of domain objects, which directly point to
their names, and a tree of zone objects, which indirectly point to
their names via a domain object. We could save a pointer per
domain (and compensate for the key pointers in leaf nodes) by
allocating a struct domain and its dname contiguously. If we do
that, we would find the domain name by pointer arithmetic
(dname_type*)(domain+1) instead of domain->dname.

When a domain name is converted to a qp-trie lookup key, it does
not need to be normalized. Can we skip the normalization step in
process_query_section(), or is there too much else that depends on
it? Comparing domain names is easier when they have been
normalized, and this code relies on that. It will need to be
adjusted if NSD is changed to normalize names less strictly.

*/
