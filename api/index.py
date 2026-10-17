"""
SafeX Vercel Serverless Entry Point
Exports the FastAPI application for Vercel's Python runtime.
"""

import sys
import os

# Add root folder to sys.path so 'safex' module is importable
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from safex.web.app import app

# Handler reference for Vercel ASGI
handler = app
