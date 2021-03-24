/*
 * fuzz-radname.c - test compact radix tree keys
 *
 * Written by Tony Finch <dot@dotat.at>
 * See LICENSE for the license.
 */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "config.h"
#include "radtree.h"

/* RFC 1035 */
#define NMAX 255

/* more than enough */
#define KMAX 400
#define DMAX 300

/* copied from radtree.c */

#define D2R_SIX_LABEL 4
#define D2R_SIX_INIT 5
#define D2R_SIX_MAX (1 << 6)

#define CONSUME_BYTE do {						\
		sixlen += 8;						\
		six4 <<= 8;						\
		six4 |= (kpos < klen ? key[kpos++] : 0);		\
	} while(0)

#define CONSUME_SIX do {						\
		if(sixlen == 0)	{					\
			CONSUME_BYTE;					\
			CONSUME_BYTE;					\
			CONSUME_BYTE;					\
		}							\
		six_one = six_two;					\
		six_two = (six4 >> 18) % D2R_SIX_MAX;			\
		six4 <<= 6;						\
		sixlen -= 6;						\
	} while(0)

#define CONSUME_START do {						\
		six_one = six_two = 0;					\
		six4 = sixlen = 0;					\
		kpos = label = 0;					\
		CONSUME_SIX;						\
		CONSUME_SIX;						\
	} while(0)


#define printf(s, ...)

extern int
LLVMFuzzerTestOneInput(const uint8_t *input, size_t size);
extern int
LLVMFuzzerTestOneInput(const uint8_t *input, size_t size) {
	uint8_t key[KMAX], dname[DMAX];
	radstrlen_type kpos, klen = KMAX;
	size_t dlen = DMAX;

	uint8_t six_one, six_two;
	unsigned six4, sixlen, label;

	/* ensure radname_d2r() is initialized (we have not constructed a
	   tree yet, which is when initialization normally happens) */
	struct radtree rt;
	radix_tree_init(&rt);

	if(size == 0)
		return(0);
	if(size > NMAX)
		return(0);

	/* Ensure the domain name fills the input. This is a bit of a
	   hack, because zero bytes are allowed inside labels, whereas
	   this excludes them. But this is the easiest way to avoid
	   triggering assertions in the non-compact radname code. */
	for(unsigned i = 0; i < size - 1; i++)
		if(input[i] == 0)
			return(0);
	if(input[size - 1] != 0)
			return(0);

	/* skip domain names containing upper case: valid label
	   lengths are less than 'A' so this doesn't affect how
	   we fuzz the structure of domain names */
	for(unsigned i = 0; i < size; i++)
		if('A' <= input[i] && input[i] <= 'Z')
			return(0);

	printf("input ");
	for(unsigned i = 0; i < size; i++) {
		if('!' <= input[i] && input[i] <= '~')
			printf("%c", input[i]);
		else
			printf("\\%03d", input[i]);
	}
	printf("\n");

	radname_d2r(key, &klen, input, size);
	if(klen == KMAX || klen == 0)
		return(0);

	printf("compact ");
	for(unsigned i = 0; i < klen; i++)
		printf("\\x%02x", key[i]);
	printf("\n");

	printf("sixes ");
	/* scan for label markers */
	CONSUME_START;
	while(six_one != 0) {
		if(six_one == D2R_SIX_LABEL) {
			printf(" .");
		} else {
			printf("%3d", six_one);
		}
		CONSUME_SIX;
	}
	printf("\n");

	radname_r2d(key, klen, dname, &dlen);

	printf("dname ");
	for(unsigned i = 0; i < dlen; i++) {
		if('!' <= dname[i] && dname[i] <= '~')
			printf("%c", dname[i]);
		else
			printf("\\%03d", dname[i]);
	}
	printf("\n");

	assert(dlen <= size);
	assert(memcmp(input, dname, dlen) == 0);

	return(0);
}
