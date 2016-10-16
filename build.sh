#!/bin/sh
# Build script for benchmark scanner cross platform binaries
# bash -z test the first argument for null string expansion, exits if it is
if [ -z "$1" ]
  then
    echo "Please run as $0 \"vN.Y\""
    echo "Error: No version argument supplied. Exiting."
    exit 1
fi
GOOS=linux GOARCH=amd64 go build -o bin/aws-cis-scanner-linux-x64-v$1 github.com/adamcrosby/aws-cis-scanner
GOOS=darwin GOARCH=amd64 go build -o bin/aws-cis-scanner-darwin-x64-v$1 github.com/adamcrosby/aws-cis-scanner
GOOS=windows GOARCH=amd64 go build -o bin/aws-cis-scanner-win-x64-v$1.exe github.com/adamcrosby/aws-cis-scanner
