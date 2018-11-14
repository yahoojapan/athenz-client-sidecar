#!/bin/sh

set -u

export GOPATH=`pwd`/../../../../
export GO111MODULE=on

go test -v -race -covermode=atomic -coverprofile=coverage.out ./... 

meta set test-result $?

go tool cover -html=coverage.out -o new_coverage.html

set -e

sha=`git rev-parse HEAD`

prefix=$1
ident=$sha

# override
if [ $# -eq 2 ] && [ ! "$2" = "" ]; then
        prefix=coverage
        ident=$2
fi

git checkout gh-pages
mv -f new_coverage.html $prefix-$ident.html

set +e

if [ -f $1.html ]; then
    rm -f $1.html
fi
ln -s $prefix-$ident.html $1.html

git add $prefix-$ident.html $1.html || true
git commit -m "Update coverage: https://pages.ghe.corp.yahoo.co.jp/athenz/athenz-tenant-sidecar/$prefix-$ident.html" || true

