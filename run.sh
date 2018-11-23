#!/bin/bash

cd $(dirname "$0")

./ban.py > out.log 2>&1
