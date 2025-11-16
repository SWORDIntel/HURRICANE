#!/bin/bash
# HURRICANE v6-gatewayd Quick Launch Wrapper
# Delegates to the master build-and-launch script

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

exec sudo "$SCRIPT_DIR/scripts/build-and-launch.sh" "$@"
