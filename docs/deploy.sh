#!/usr/bin/env bash

cd "$(dirname "${BASH_SOURCE[0]}")/_build/html"


if [[ ! -d .git ]]; then
    git init .
fi

touch .nojekyll

git add .
git commit -m "$(date)"

git push -f git@github.com:mikeboers/Flask-ACL.git HEAD:gh-pages
