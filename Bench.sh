#!/bin/sh

set -eu

make treeperf

if [ ! -f top-1m.csv.zip ]
then curl -o top-1m.csv.zip \
	  http://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip
fi

if [ ! -f top-1m.csv ]
then unzip top-1m.csv.zip top-1m.csv
fi

if [ ! -f top-1m.list ]
then sed 's///;s/^[0-9]*,//' <top-1m.csv >top-1m.list
fi

for i in rb rad qp;
do  echo $i;
    ./${i}treeperf count top-1m.list;
    ./${i}treeperf time top-1m.list;
done
