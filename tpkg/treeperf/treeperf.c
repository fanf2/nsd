/*
 * treeperf.c -- simple program to measure memory usage per backend
 *
 * Copyright (c) 2001-2020, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */

#include "config.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "talloc.h"
#include "util.h"
#include "dname.h"
#include "namedb-treeperf.h"
#include "pcg64.h"

#define MAX_DOMAINS 1111111

#define BENCHMARK_LOOPS 1000000

static pcg64_t rng;

static dname_type *
random_dname(region_type *region)
{
  uint8_t buf[256];
  int labels, lab, len, i, off;
  const dname_type *dname;

  off = 0;
  labels = pcg64_limit(&rng, 4) + 3;
  for (lab = 0; lab < labels; lab++) {

    len = pcg64_limit(&rng, 4) + 4;
    assert(off + len + 1 < 255);

    buf[off++] = (uint8_t)len;
    for (i = 0; i < len; i++) {
      buf[off++] = (uint8_t)('a' + pcg64_limit(&rng, 26));
    }
  }
  buf[off++] = 0;

  dname = dname_make(region, buf, 1);
  assert(dname != NULL);
  return((struct dname *)dname);
}

static void
typo_dname(dname_type *dname)
{
  const uint8_t *label, *data;
  int lab, off, i;
  uint8_t *raw;

  /* skip root label */
  lab = pcg64_limit(&rng, dname->label_count - 1) + 1;
  label = dname_label(dname, lab);
  data = label_data(label);
  off = pcg64_limit(&rng, label_length(label));
  // cast away const */
  raw = (uint8_t*)dname;
  i = data + off - raw;
  raw[i] = (uint8_t)('a' + pcg64_limit(&rng, 26));
}

static void
time_lookups(const char *tag, struct domain_table *table,
	     struct dname *list[], int count)
{
  struct timespec tv0, tv;
  struct dname *dname;
  struct domain *match, *encloser;
  int i, found, missing;

  found = 0;
  get_time(&tv0);
  for (i = 0; i < BENCHMARK_LOOPS; i++) {
    dname = list[pcg64_limit(&rng, count)];
    found += domain_table_search(table, dname, &match, &encloser);
  }
  get_time(&tv);
  timespec_subtract(&tv, &tv0);
  missing = BENCHMARK_LOOPS - found;
  printf("%s %d/%d %ld.%09ld seconds\n",
	 tag, found, missing , tv.tv_sec, tv.tv_nsec);
}

static void usage(const char *prog)
{
  fprintf(stderr, "Usage: %s READ|COUNT|TIME FILE\n", prog);
  exit(1);
}

#define READ (0)
#define COUNT (1)
#define TIME (2)

int main(int argc, char *argv[])
{
  FILE *file;
  char line[256];
  int mode;
  struct dname *dname;
  struct region *dname_region, *table_region;
  struct domain_table *table = NULL;
  struct domain *domain;

  struct timespec tv, tv0, tv1;

  static struct dname *dname_list[MAX_DOMAINS];
  int count, i;

  pcg64_getentropy(&rng);

  dname_region = region_create(xalloc, free);
  if (argc != 3) {
    usage(argv[0]);
  } else if (strcmp(argv[1], "read") == 0) {
    mode = READ;
  } else if (strcmp(argv[1], "count") == 0) {
    table_region = region_create(talloc, tfree);
    mode = COUNT;
  } else if (strcmp(argv[1], "time") == 0) {
    table_region = region_create(xalloc, free);
    mode = TIME;
  } else {
    usage(argv[0]);
  }

  assert(dname_region != NULL);
  if (mode == COUNT || mode == TIME) {
    assert(table_region != NULL);
    table = domain_table_create(table_region);
  }

  if ((file = fopen(argv[2], "rb")) == NULL) {
    fprintf(stderr, "Cannot open %s, %s\n", argv[2], strerror(errno));
    exit(1);
  }

  get_time(&tv0);

  count = 0;
  while (count < MAX_DOMAINS &&
	 fgets(line, sizeof(line), file) != NULL) {
    size_t len = strlen(line);
    /* skip short names so that the typo generator doesn't hang */
    if (len < 5)
      continue;
    if (line[len-1] == '\n')
      line[--len] = '\0';
    /* cast away const */
    dname = (struct dname *)dname_parse(dname_region, line);
    if (dname == NULL) {
      fprintf(stderr, "Cannot make dname from %s\n", line);
      exit(1);
    }
    dname_list[count++] = dname;
    if (mode != READ) {
      domain = domain_table_insert(table, dname);
      if (domain == NULL) {
        fprintf(stderr, "Cannot insert %s\n", line);
        exit(1);
      }
    }
  }

#ifdef TREEPERF_USE_QP
  qp_compact(table->nametree.qp);
  qp_release(table->nametree.qp);
#endif

  get_time(&tv);
  timespec_subtract(&tv, &tv0);

  if (mode == TIME) {

    time_lookups("yxdomain", table, dname_list, count);

    get_time(&tv0);
    for (i = 0; i < count; i++) {
      struct domain *match, *encloser;
      dname = dname_list[i];
      while(domain_table_search(table, dname, &match, &encloser)) {
	typo_dname(dname);
      }
    }
    get_time(&tv1);
    timespec_subtract(&tv1, &tv0);
    timespec_add(&tv, &tv1);

    time_lookups("typo    ", table, dname_list, count);

    get_time(&tv0);
    for (i = 0; i < count; i++) {
      struct domain *match, *encloser;
      do {
	dname = dname_list[i];
	region_recycle(dname_region, dname, dname_total_size(dname));
	dname_list[i] = random_dname(dname_region);
      } while(domain_table_search(table, dname, &match, &encloser));
    }
    get_time(&tv1);
    timespec_subtract(&tv1, &tv0);
    timespec_add(&tv, &tv1);

    time_lookups("nxdomain", table, dname_list, count);

    printf("overhead %ld.%09ld seconds\n", tv.tv_sec, tv.tv_nsec);
  }

  for (i = 0; i < count; i++) {
    dname = dname_list[i];
    region_recycle(dname_region, dname, dname_total_size(dname));
  }

  if (mode == COUNT) {
#ifdef TREEPERF_USE_QP
    size_t total = 0;
    total += qp_print_memstats(stdout, table->nametree.qp);
    total += print_talloc_stats();
    printf("%zu total allocated (%.3f MiB)\n",
	   total, (double)total / 1048576);
#else
    print_talloc_stats();
#endif
  }

  return 0;
}
