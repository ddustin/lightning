#!/bin/bash

git add $(rebase_fix $(git ls-files -u  | cut -f 2 | sort -u))
