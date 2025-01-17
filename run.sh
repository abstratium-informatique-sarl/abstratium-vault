#!/bin/bash

~/go/bin/air --build.cmd "go build -o bin/vault ." --build.bin "bin/vault" --build.exclude_dir "tmp,web" --build.stop_on_error true

