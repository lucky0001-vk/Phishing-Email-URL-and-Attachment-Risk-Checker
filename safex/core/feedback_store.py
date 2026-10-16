"""
SafeX User Feedback Store
Records user reports for incorrect classifications, false positives, and false negatives
to evaluate engine accuracy and guide future rule adjustments.
"""

import json
import os
import threading
from datetime import datetime, timezone
from typing import Dict, Any, List

FEEDBACK_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "feedback_store.json")
_lock = threading.Lock()


def _load_data() -> Dict[str, Any]:
    if not os.path.exists(FEEDBACK_FILE):
        return {
            "created_at": datetime.now(timezone.utc).isoformat(),
            "feedbacks": []
        }
    try:
        with open(FEEDBACK_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {"created_at": datetime.now(timezone.utc).isoformat(), "feedbacks": []}


def _save_data(data: Dict[str, Any]):
    temp_file = FEEDBACK_FILE + ".tmp"
    with open(temp_file, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    os.replace(temp_file, FEEDBACK_FILE)


def record_feedback(entry: Dict[str, Any]) -> Dict[str, Any]:
    """
    Record classification feedback:
    entry = {
        "sample_id": str/int,
        "sample_name": str,
        "user_verdict": "FALSE_POSITIVE" | "FALSE_NEGATIVE" | "ACCURATE",
        "notes": str,
        "assigned_score": int,
        "assigned_rating": str,
        "flagged_components": list (e.g. ['sender', 'body', 'url', 'attachment'])
    }
    """
    with _lock:
        data = _load_data()
        record = {
            "id": f"fb-{len(data['feedbacks']) + 1:04d}",
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
            "sample_id": entry.get("sample_id", "custom"),
            "sample_name": entry.get("sample_name", "User Ingested Sample"),
            "user_verdict": entry.get("user_verdict", "ACCURATE").upper(),
            "notes": entry.get("notes", "").strip(),
            "assigned_score": entry.get("assigned_score", 0),
            "assigned_rating": entry.get("assigned_rating", "LOW"),
            "flagged_components": entry.get("flagged_components", []),
        }
        data["feedbacks"].append(record)
        _save_data(data)
        return record


def get_feedback_stats() -> Dict[str, Any]:
    """Calculate aggregated metrics on user-reported classifications."""
    with _lock:
        data = _load_data()
        feedbacks: List[Dict[str, Any]] = data.get("feedbacks", [])

    total = len(feedbacks)
    false_positives = sum(1 for f in feedbacks if f.get("user_verdict") == "FALSE_POSITIVE")
    false_negatives = sum(1 for f in feedbacks if f.get("user_verdict") == "FALSE_NEGATIVE")
    accurate = sum(1 for f in feedbacks if f.get("user_verdict") == "ACCURATE")

    user_accuracy = round((accurate / total * 100), 1) if total > 0 else 100.0

    return {
        "total_reports": total,
        "accurate_count": accurate,
        "false_positive_count": false_positives,
        "false_negative_count": false_negatives,
        "user_verified_accuracy_pct": user_accuracy,
        "recent_feedbacks": feedbacks[-10:][::-1]  # Most recent 10
    }
