# SafeX Vercel Deployment Guide

This document contains the exact deployment settings required to deploy **SafeX** onto **Vercel** with zero errors.

---

## 1. Quick Copy-Paste Deployment Checklist

When importing this repository into Vercel, copy these exact settings:

| Setting | Required Value | Notes |
| :--- | :--- | :--- |
| **Project Name** | `safex` (or your choice) | Any alphanumeric name |
| **Framework Preset** | **`Other`** | Do **NOT** choose Next.js, Vite, or React |
| **Root Directory** | **`./`** | **Must remain `./`** (do not select subfolders) |
| **Build Command** | *Leave Empty / Toggle OFF* | No compilation needed (static frontend) |
| **Output Directory** | *Leave Empty / Toggle OFF* | Managed dynamically by `vercel.json` |
| **Install Command** | *Leave Empty / Toggle OFF* | Vercel automatically runs `pip install -r requirements.txt` |
| **Development Command** | *Leave Empty / Toggle OFF* | `python -m uvicorn safex.web.app:app --port 8000` (optional) |
| **Environment Variables** | *Leave Completely Empty* | Engine is 100% self-contained & air-gapped |

---

## 2. Detailed Setting-by-Setting Breakdown

### 1. Root Directory: `./`
* **What folder should I select?** Leave it as the default (`./`).
* **Why?** 
  - `vercel.json` is located at the root (`./vercel.json`).
  - `requirements.txt` is located at the root (`./requirements.txt`).
  - `api/index.py` (the Python Serverless ASGI handler) is located at `./api/index.py`.
  - Static UI assets are located at `./safex/web/static/`.
  - Changing the Root Directory will break path resolution and cause the build to fail.

### 2. Application Framework Preset: `Other`
* **Why?** SafeX combines a Python FastAPI backend with a vanilla Material Design 3 frontend (HTML5/CSS3/JavaScript). It does not use Node.js frameworks. Selecting **`Other`** allows Vercel to read `vercel.json` and configure the Python Serverless runtime without looking for Node.js build tools.

### 3. Build & Output Settings
* **Build Command**: Toggle **OFF** / Leave blank.
* **Output Directory**: Toggle **OFF** / Leave blank.
* **Install Command**: Toggle **OFF** / Leave blank.
  - Vercel automatically detects `requirements.txt` and installs `fastapi`, `uvicorn`, `pydantic`, `python-multipart`, and `python-dotenv`.
* **Development Command**: Toggle **OFF** / Leave blank.

### 4. Environment Variables: None Required (Leave Empty)
* **Required variables**: **0** (Leave the Environment Variables section empty).
* **Why SafeX needs no environment variables**:
  - **Zero External API Dependencies**: Detection heuristics, optical URL mismatch detection, and MIME signature matrices run completely in-memory.
  - **No Database Needed**: Test samples and benchmark sets are pre-bundled.
  - **Serverless Storage Compliant**: The feedback store automatically writes to `/tmp/safex_feedback_store.json` on Vercel's read-only serverless filesystem.
  - **CORS Pre-Configured**: CORS is set to `*` to allow seamless dashboard communication.

---

## 3. Architecture on Vercel

```
User Browser / API Client
         │
         ▼
  Vercel Edge Gateway (vercel.json)
    ├── /api/*   ──────► api/index.py (FastAPI ASGI Serverless Function)
    │                         └── safex.core.analyzer (In-Memory Heuristics)
    └── /*       ──────► safex/web/static/* (Material Design 3 Dashboard)
```

---

## 4. Troubleshooting & Traps to Avoid

1. **"Invalid configuration: should not have additional property 'public'":**
   - **Resolved**: Top-level `"public"` is prohibited in Vercel v2 schema. `vercel.json` has already been updated to comply with Vercel v2 schema.
2. **Missing `api/index.py`:**
   - **Resolved**: `api/index.py` exports `handler = app` specifically for Vercel's Python runtime.
3. **Do not create a `package.json` file:**
   - Creating an empty `package.json` causes Vercel to assume the project is Node.js, overriding the Python runtime.
