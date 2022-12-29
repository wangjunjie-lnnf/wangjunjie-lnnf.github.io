---
layout: post
title:  "Setup Jekyll!"
date:   2022-12-29 14:32:07 +0800
categories: jekyll
tags: jekyll
---

### setup jekyll
1. open http://github.io and read the doc
2. open https://jekyllrb.com/docs/ and read the doc
3. add posts in `_posts` dir and run `jekyll serve` to update 
4. run `git add .` and `git commit -m 'xxx'` and `git push`

### install protobuf error on mac m1
1. see https://github.com/protocolbuffers/protobuf/issues/8199
2. run `gem uninstall google-protobuf` and `gem install google-protobuf -v 3.15.8 --platform=ruby`
