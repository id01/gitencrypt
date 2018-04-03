#!/bin/bash

gcc git_encrypt.c header/shoco/shoco.o header/z85/src/libZ85.a header/scrypt-jane/scrypt-jane.o -lcrypto -ldeflate -lgcov -o git_encrypt $@
