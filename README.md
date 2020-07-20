# NSD

The NLnet Labs Name Server Daemon (NSD) is an authoritative DNS name server.

This fork of NSD can be configured so that the core domain name lookup
data structure is a [DNS-specific qp-trie](https://dotat.at/prog/qp/);
build with `./configure --use-qp-trie`


build and test
--------------

The `./Build.sh` script will configure and compile NSD for my test
setup, and run the `cutest` unit tests. There are multiple builds, for
each of the different possible name lookup trees. The builds are
installed in the subdirectory `./IN/` in the source tree. Each
`IN/bin/nsd-*` binary has a suffix indicating its configuration.


benchmark
---------

With any build configuration, you can run `./Bench.sh`. This compiles
several versions of a small benchmark program which exercises NSD's
name lookup trees. The script will download the Cisco Umbrella top-1m
domain list (if necessary) before running the benchmarks. The
benchmark is single-threaded; it counts the time for a million lookups
of:

  * `yxdomain`: known domain names

  * `typo`: unknown domain names that are similar to known names

  * `nxdomain`: completely random domain names

The versions are:

  * `radtreeperf`: NSD's default radix tree

  * `rbtreeperf`: NSD's alternative red-black tree

  * `qptreeperf`: my DNS-optimized qp-trie


The following results were run on an Apple MacBook Pro
(16" 2019, 2.6GHz Intel i7):

    rb
    yxdomain 1000000/0 1.658168000 seconds
    typo     0/1000000 1.370699000 seconds
    nxdomain 0/1000000 0.575745000 seconds
    98307984 bytes allocated (93.754 MiB)
    rad
    yxdomain 1000000/0 1.069693000 seconds
    typo     0/1000000 0.912661000 seconds
    nxdomain 0/1000000 0.345298000 seconds
    354436840 bytes allocated (338.017 MiB)
    qp
    yxdomain 1000000/0 0.683194000 seconds
    typo     0/1000000 0.810722000 seconds
    nxdomain 0/1000000 0.362822000 seconds
    151737648 bytes allocated (144.708 MiB)

The following results were from an earlier version of the qp-trie
code, run on an Intel i7-4770 3.4GHz.

    rb
    99729296 bytes allocated
    yxdomain 1000000/0 1.612399592 seconds
    typo     0/1000000 1.436897592 seconds
    nxdomain 0/1000000 0.538228288 seconds
    rad
    355016648 bytes allocated
    yxdomain 1000000/0 0.865918251 seconds
    typo     0/1000000 0.822637818 seconds
    nxdomain 0/1000000 0.292481364 seconds
    qp
    152805552 bytes allocated
    yxdomain 1000000/0 0.577171742 seconds
    typo     0/1000000 0.759439270 seconds
    nxdomain 0/1000000 0.287439416 seconds


## Known problem areas

This fork of NSD has only been very lightly tested.

_Tony Finch <dot@dotat.at>_
