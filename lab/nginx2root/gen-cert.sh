#!/bin/sh
# Self-signed certificate for the lab only.
set -e
cd "$(dirname "$0")"
mkdir -p certs
openssl req -x509 -newkey rsa:2048 -nodes -days 30 \
  -keyout certs/key.pem -out certs/cert.pem -subj "/CN=nginx2root.lab" 2>/dev/null
chmod 644 certs/key.pem certs/cert.pem
echo "Wrote certs/cert.pem and certs/key.pem"
