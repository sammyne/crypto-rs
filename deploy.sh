#!/usr/bin/env sh

# abort on errors
set -e

# publish the latest release to the master branch
git push -f git@github.com:sammyne/cryptographer.git HEAD:master

# build
cargo doc --no-deps

# navigate into the build output directory
cd target/doc

# if you are deploying to a custom domain
# echo 'www.example.com' > CNAME

git init
git add -A
# add [skip ci] to instruct CircleCI to skip this deployment
git commit -m 'deploy doc [skip ci]'

# release document to the doc branch
# if you are deploying to https://<USERNAME>.github.io
git push -f git@github.com:sammyne/cryptographer.git HEAD:gh-pages

# if you are deploying to https://<USERNAME>.github.io/<REPO>
# git push -f git@github.com:<USERNAME>/<REPO>.git master:gh-pages

cd -