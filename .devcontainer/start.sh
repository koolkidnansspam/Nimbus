#!/bin/bash
cd "$(dirname "$0")/.."

# Start Nimbus without giving it the GitHub token
env -u GH_TOKEN nohup node server.js > /tmp/nimbus.log 2>&1 &

# Make port 8080 public (retry until the port is ready)
for i in $(seq 1 12); do
  sleep 5
  if gh codespace ports visibility 8080:public -c "$CODESPACE_NAME" >> /tmp/ports.log 2>&1; then
    break
  fi
done
