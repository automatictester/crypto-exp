#!/bin/bash

if [ "$#" -ne 1 ]; then
  SCRIPT_NAME=$(basename "$0")
  echo "Usage: ${SCRIPT_NAME} filename"
  exit 1
fi

if [ ! -f "$1" ]; then
  echo "File '$1' does not exist"
  exit 1
fi

if [ ! -r "$1" ]; then
  echo "File '$1' is not readable"
  exit 1
fi

if [ ! -s "$1" ]; then
  echo "File '$1' is empty"
  exit 1
fi
