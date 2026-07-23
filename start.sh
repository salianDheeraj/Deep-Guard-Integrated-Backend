#!/bin/sh

# Make ML engine import paths point to the correct root
export PYTHONPATH="/usr/src/app/app/Deep-Guard-ML-Engine"

echo "🚀 Starting Deep Guard System..."

# 1. Start ML engine (Python) in background
echo "   - Launching Python ML Engine..."
uvicorn app.main:app --host 0.0.0.0 --port 8000 --timeout-keep-alive 600 &

# Wait for Python to initialize
sleep 5

# 2. Start Backend (Node.js) in foreground
echo "   - Launching Node.js Backend..."
cd app/Deep-Guard-Backend
PORT=${PORT:-5000}

node server.js