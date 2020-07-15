#!/bin/sh

set -eux

IN=$(pwd)/IN

aclocal && autoconf && autoheader

build() {
	suffix=$1
	shift

	CFLAGS='-g -O2 -march=native' \
	./configure --prefix=${IN} \
		    --sbindir=${IN}/bin \
		    --mandir=${IN}/man \
		    --docdir=${IN}/doc \
		    --with-configdir=${IN}/etc \
		    --with-logfile=${IN}/var/nsd.log \
		    --with-pidfile=${IN}/var/nsd.pid \
		    --with-dbfile=${IN}/var/nsd.db \
		    --with-zonesdir=${IN}/zone \
		    --with-xfrdfile=${IN}/var/xfrd.state \
		    --with-zonelistfile=${IN}/zone.list \
		    --with-xfrdir=${IN}/tmp \
		    --enable-checking \
		    --enable-memclean \
		    --enable-bind8-stats \
		    --enable-zone-stats \
		    "$@"

	make clean all cutest install

	./cutest

	grep TR[IE]E config.h

	mv ${IN}/bin/nsd ${IN}/bin/nsd-$suffix
}

build rad --enable-radix-tree

build qp --enable-qp-trie

build rb

mkdir -p ${IN}/zone
ln -sf ../../nsd.conf ${IN}/etc/nsd.conf
