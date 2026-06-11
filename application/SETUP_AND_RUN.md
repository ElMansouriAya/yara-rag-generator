# 🚀 YARA RAG Generator — Complete Setup & Run Guide

## What You Have

A complete, production-ready YARA rule generation system with:
- ✅ Frontend dashboard (Next.js React UI)
- ✅ Backend RAG pipeline (Python with 4 modes)
- ✅ **NEW** Flask HTTP API server (fully integrated)
- ✅ 3 LLM models (Qwen, Flan, Mistral)
- ✅ Knowledge base with 3046+ documents
- ✅ Comprehensive error handling
- ✅ Full documentation

---

## 🎯 Quick Setup (5 minutes)

### 1️⃣ Install Server Dependencies

```bash
pip install flask flask-cors python-dotenv
```

Or use the requirements file:
```bash
pip install -r requirements-server.txt
```

### 2️⃣ Start Flask API Server

```bash
python run_server.py
```

✅ You should see:
```
YARA RAG Generator — Flask Server
Host:           0.0.0.0:5000
Starting server... (Press Ctrl+C to stop)
```

### 3️⃣ Start Frontend (in another terminal)

```bash
cd frontend
pnpm dev
```

✅ You should see:
```
  ▲ Next.js 15
  - Ready in 1234ms
  - Local: http://localhost:3000
```

### 4️⃣ Open Dashboard

Go to `http://localhost:3000` in your browser.

✅ You're done! The dashboard should load with a working backend connection.

---

## ✨ What Each File Does

### Server Files (NEW - Implements HTTP API)

| File | Purpose |
|------|---------|
| **server.py** | Flask HTTP API with 7 endpoints |
| **run_server.py** | Entry point script with CLI options |
| **requirements-server.txt** | Flask dependencies |
| **.env.example** | Configuration template |
| **.env** | Your local config (copy from .env.example) |

### Frontend Files (EXISTING - Updated with env)

| File | Purpose |
|------|---------|
| **frontend/.env.local** | Sets API_URL to localhost:5000 |
| **frontend/lib/api-client.ts** | HTTP client for 7 endpoints |
| **frontend/app/page.tsx** | Main dashboard |
| **frontend/components/** | All UI components |

### Documentation Files (NEW - Comprehensive guides)

| File | Purpose |
|------|---------|
| **QUICK_START.md** | 2-minute quick reference |
| **SERVER_INTEGRATION_GUIDE.md** | Complete API documentation |
| **INTEGRATION_SUMMARY.md** | What was added and why |
| **FUNCTIONALITY_CHECKLIST.md** | Feature completeness |
| **This file** | Master setup guide |

### Testing & Utilities

| File | Purpose |
|------|---------|
| **test_integration.sh** | Automated endpoint testing |

---

## 📚 Documentation Structure

```
START HERE:
├── QUICK_START.md (2 min read)
│   └── Get running immediately
│
THEN READ:
├── INTEGRATION_SUMMARY.md (what changed)
│   └── Understand the architecture
│
FOR DETAILS:
├── SERVER_INTEGRATION_GUIDE.md (complete reference)
│   ├── All 7 API endpoints
│   ├── Request/response examples
│   ├── Configuration options
│   ├── Troubleshooting
│   └── Deployment guide
│
FOR VERIFICATION:
├── FUNCTIONALITY_CHECKLIST.md (what works)
│   └── Complete feature list
│
FOR TESTING:
└── test_integration.sh (automated tests)
    └── Run: chmod +x test_integration.sh && ./test_integration.sh
```

---

## 🔧 Server Commands

### Start Server

```bash
# Default (Qwen model, port 5000)
python run_server.py

# Custom port
python run_server.py --port 8000

# Different model
python run_server.py --model mistral

# Debug mode
python run_server.py --debug

# Production mode
python run_server.py --prod

# Combined
python run_server.py --port 8000 --model mistral --debug
```

### Configuration

Edit `.env` for persistent settings:
```
FLASK_ENV=development
FLASK_PORT=5000
DEFAULT_MODEL=qwen
```

---

## 🎨 Dashboard Features

### Generate Tab
- Input: Natural language threat description
- Output: YARA rule + sources + explanation
- Modes: agentic, hybrid, classic, baseline
- Models: qwen, flan, mistral

### Search Tab
- Search the knowledge base
- See similar YARA rules
- Review document sources

### Benchmark Tab
- Compare all 4 RAG modes
- Run on custom queries
- Export metrics

### Stats Tab
- View dataset statistics
- Distribution by malware type
- Top malware families

### Model Selector (Header)
- Switch between 3 LLM models
- Change takes effect immediately
- No need to restart server

---

## 🧪 Test It Out

### Manual Testing with curl

```bash
# Health check
curl http://localhost:5000/health

# Generate rule
curl -X POST http://localhost:5000/api/generate \
  -H "Content-Type: application/json" \
  -d '{"query":"Ransomware with AES","mode":"baseline"}'

# Search KB
curl -X POST http://localhost:5000/api/search \
  -H "Content-Type: application/json" \
  -d '{"query":"ransomware","k":5}'

# Get stats
curl http://localhost:5000/api/stats

# Switch model
curl -X POST http://localhost:5000/api/model \
  -H "Content-Type: application/json" \
  -d '{"model":"mistral"}'
```

### Automated Testing

```bash
chmod +x test_integration.sh
./test_integration.sh

# Or test against custom server
./test_integration.sh http://localhost:8000
```

---

## 🎯 Common Workflows

### Generate Your First YARA Rule

1. Open dashboard at `http://localhost:3000`
2. Go to **Generate** tab
3. Enter: `Ransomware encrypting files and demanding payment`
4. Select mode: **agentic** (best quality)
5. Click **Generate**
6. View the generated rule, syntax score, and sources

### Find Similar Rules

1. Go to **Search** tab
2. Enter: `AES encryption malware`
3. View matching documents from knowledge base
4. Click on any result to see full YARA rule

### Compare RAG Modes

1. Go to **Benchmark** tab
2. Click **Load Example Queries**
3. Click **Run Benchmark**
4. Compare metrics across modes
5. See which mode works best for your use case

### Switch Models & Try Again

1. Open **Header** (top right)
2. Select different model (Qwen → Flan → Mistral)
3. Go back to **Generate** tab
4. Generate same rule with different model
5. Compare quality & speed

---

## 📊 Performance Tips

### Fastest Setup
- Model: **Qwen** (default)
- Mode: **baseline**
- Location: Local machine with GPU (if available)

### Best Quality
- Model: **Mistral** (7B)
- Mode: **agentic**
- Time: 5-10 minutes per query

### Balanced
- Model: **Flan**
- Mode: **hybrid**
- Time: 2-3 minutes per query

---

## 🐛 Troubleshooting

### "Port 5000 already in use"
```bash
python run_server.py --port 8000
```

### "API server is not available"
1. Check Flask server is running
2. Check `frontend/.env.local` has `NEXT_PUBLIC_API_URL=http://localhost:5000`
3. Test with: `curl http://localhost:5000/health`

### "Module not found" (transformers, torch, etc.)
```bash
pip install -r requirements.txt
```

### Slow generation
Switch to Qwen model: `python run_server.py --model qwen`

### More help?
See **SERVER_INTEGRATION_GUIDE.md** → Troubleshooting section

---

## 🚀 Deployment

### Docker

```dockerfile
FROM python:3.10-slim
WORKDIR /app
COPY . .
RUN pip install -r requirements.txt -r requirements-server.txt
EXPOSE 5000
CMD ["python", "run_server.py", "--prod"]
```

### Environment Variables

```bash
# Development
FLASK_ENV=development
FLASK_PORT=5000
DEFAULT_MODEL=qwen

# Production
FLASK_ENV=production
FLASK_PORT=5000
DEFAULT_MODEL=mistral
```

### Production Setup

1. Set `NEXT_PUBLIC_API_URL` in frontend to deployed server
2. Enable CORS for your domain
3. Use production model (Mistral for best quality)
4. Add monitoring/logging
5. Set up SSL/HTTPS

---

## 📋 What Was Added

### ✅ Flask Server
- `server.py` (487 lines) — HTTP API with 7 endpoints
- `run_server.py` (124 lines) — CLI entry point

### ✅ Configuration
- `requirements-server.txt` — Dependencies
- `.env.example` — Configuration template
- `frontend/.env.local` — API URL setup

### ✅ Documentation
- `QUICK_START.md` — 2-minute guide
- `SERVER_INTEGRATION_GUIDE.md` — 700-line complete reference
- `INTEGRATION_SUMMARY.md` — Architecture overview
- `FUNCTIONALITY_CHECKLIST.md` — Feature completeness

### ✅ Testing
- `test_integration.sh` — Automated test suite

---

## ✅ Integration Checklist

- [x] Flask server created and fully implemented
- [x] 7 API endpoints working
- [x] CORS enabled for frontend
- [x] Request validation on all endpoints
- [x] Error handling with meaningful messages
- [x] Configuration files created
- [x] Frontend environment setup
- [x] Comprehensive documentation
- [x] Test script for verification
- [x] Quick start guide
- [x] Full API reference
- [x] Troubleshooting guide
- [x] Deployment instructions

---

## 🎓 Next Steps

1. ✅ Follow **QUICK_START.md** (5 minutes)
2. ✅ Try generating your first rule
3. ✅ Explore all dashboard features
4. ✅ Read **SERVER_INTEGRATION_GUIDE.md** for details
5. ✅ Run `test_integration.sh` to verify all endpoints
6. ✅ Deploy to your environment

---

## 📞 Support

| Question | Answer |
|----------|--------|
| How do I start? | `QUICK_START.md` |
| How does it work? | `SERVER_INTEGRATION_GUIDE.md` |
| Is everything done? | `FUNCTIONALITY_CHECKLIST.md` |
| I have an error | `SERVER_INTEGRATION_GUIDE.md` → Troubleshooting |
| How do I deploy? | `SERVER_INTEGRATION_GUIDE.md` → Deployment |
| How do I test? | Run `./test_integration.sh` |

---

## 🎉 Summary

You now have a **complete, fully integrated YARA RAG system**:

```
┌─────────────────────────────────┐
│  Next.js Dashboard (Port 3000)   │
│  - 4 tabs with full features     │
│  - Real-time results             │
│  - Model switcher                │
└──────────────┬──────────────────┘
               │ HTTP
               ▼
┌─────────────────────────────────┐
│  Flask API Server (Port 5000)    │
│  - 7 endpoints                   │
│  - Request validation            │
│  - Error handling                │
└──────────────┬──────────────────┘
               │ Python API
               ▼
┌─────────────────────────────────┐
│  RAG Pipeline                    │
│  - 4 modes (baseline → agentic)  │
│  - 3 LLM models                  │
│  - 3046+ KB documents            │
│  - Full validation               │
└─────────────────────────────────┘
```

**All systems working. Ready to generate YARA rules!** 🚀

---

**Last Updated**: June 11, 2025
**Status**: ✅ Complete & Production Ready
