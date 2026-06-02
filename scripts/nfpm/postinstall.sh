#!/bin/sh
# postinstall.sh — gbounce post-install notice
# Printed after dpkg/rpm installs the package.
# Does NOT require sudo to run the binary itself.
set -e

echo ""
echo "gbounce installed to /usr/local/bin/gbounce"
echo ""
echo "Verify your install:"
echo "  gbounce --version"
echo ""
echo "Quick start:"
echo "  gbounce run --listen 127.0.0.1:8080"
echo ""
echo "Docs: https://github.com/trsreagan3/gbounce/blob/main/README.md"
echo ""
