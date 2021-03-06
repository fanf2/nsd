/*
 * qp-trie - a DNS-specific quelques-bits popcount trie for NSD
 *
 * Written by Tony Finch <dot@dotat.at>
 * See LICENSE for the license.
 */
#ifndef QP_TRIE_H
#define QP_TRIE_H

/*
 * Type-punned words, that can be a 64-bit integer or a pointer.
 */
#if UINTPTR_MAX < UINT32_MAX
#error pointers must be at least 32 bits
#elif UINTPTR_MAX < UINT64_MAX
typedef uint64_t qp_word;
#else
typedef uintptr_t qp_word;
#endif

/*
 * A qp-trie node is a pair of words, which can be a leaf or a branch.
 *
 * In a branch:
 *
 * `ptr` is a pointer to the "twigs", a packed sparse vector of
 * child nodes.
 *
 * `index` contains the bitmap and offset that describe the twigs.
 * The bottom bit is a non-zero tag.
 *
 * In a leaf:
 *
 * `ptr` points to a struct dname.
 *
 * `index` is cast from a void* value, which must be word aligned
 * so that the bottom tag bit is zero.
 */
typedef struct qp_node {
	void *ptr;
	qp_word index;
} qp_node;

/*
 * A qp-trie
 */
struct qp_trie {
	/** the root node */
	qp_node root;
	/** count of number of elements */
	size_t count;
	/** region for allocation */
	struct region *region;
};

/*
 * Initialize a qp_trie
 */
static inline struct qp_trie
qp_empty(struct region *region)
{
	struct qp_trie t = {
		{ 0, 0, },
		0, region,
	};
	return t;
}

/*
 * Neighbours of a newly added item
 */
struct prev_next {
	void *prev, *next;
};

/*
 * Add an item to a qp_trie, and return its neighbours
 */
struct prev_next qp_add(struct qp_trie *t, const dname_type *dname, void *val);

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
void qp_foreach(qp_node *n, void (*fn)(void *val, void *ctx), void *ctx);

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

A qp-trie leaf node is a little bit flabby because it's often the
case that the value object wants to contain the key as well, so
the pointer in the leaf node is a bit redundant. But the leaf node
itself can't be used as a proxy for the value object, because
nodes move around when their containers are reallocated. So it's
difficult to eliminate the redundancy.

A rough estimate of qp-trie memory usage is three words per
object: key pointer, value pointer, and about one word of overhead
for internal branching. (It varies between about 0.5 and 1.5 words
per object depending on the set of keys.) In NSD we are adding
prev+next pointers to each domain object as well. So we expect the
qp-trie to use about 5 words per domain.

By comparison, NSD's radtree structure uses 5 words per domain
plus overhead for internal branching. (I don't know how much that
typically is, but I expect it can be a lot.) The rbtree structure
normally uses 4 words per domain.

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
