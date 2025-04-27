"""
Salesforce → Meta Sync with Human Approval Workflow
===================================================
Author: OpenAI ChatGPT (o3 reasoning model)
Updated: 2025‑04‑27

Overview
--------
Leads still **flow into Salesforce automatically** (e.g. via Zapier).  
A *human* then marks each lead **Good** or **Bad** inside Salesforce (checkbox **`Good_Approved__c`**) or via a spreadsheet import that maps to this field.  
This script **only exports the “Good” leads** back to Meta — either to a **Custom Audience** *or* the **Conversions API** — and then flags them as **exported** so they are not sent twice.

Key features
------------
* **Two‑stage filter**: `Good_Approved__c = true` **and** `MetaExported__c = false`.
* **After upload** the script bulk‑updates `MetaExported__c = true` on the same Lead records.
* **Choice of destination**:
  * *Custom Audience* (default).  
  * *Conversions API* (set `META_DESTINATION=CONVERSIONS`) to fire a `LeadApproved` event.
* Robust logging, retry + back‑off, idempotent cursor, env‑driven config.

Dependencies
------------
```bash
pip install simple-salesforce python-dotenv requests tenacity
```

Environment
-----------
```text
# Salesforce
SF_USERNAME=···
SF_PASSWORD=···
SF_SECURITY_TOKEN=···
SF_DOMAIN=login                  # change to "test" for sandbox

# Custom field API names (adjust to match your org)
SF_APPROVAL_FIELD=Good_Approved__c
SF_EXPORTED_FIELD=MetaExported__c

# Meta / Facebook
META_ACCESS_TOKEN=EAAB…
META_AD_ACCOUNT_ID=act_123456789012345
META_CUSTOM_AUDIENCE_ID=987654321098765
META_PIXEL_ID=123456789098765        # required only for Conversions API
META_DESTINATION=AUDIENCE            # or CONVERSIONS

# General
LOG_LEVEL=INFO
SYNC_WINDOW_MINUTES=10
```

Usage
-----
```bash
python salesforce_meta_sync.py           # one‑off run
# or schedule every 5–15 min via cron / Cloud scheduler / GitHub Action
```
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List, Dict

import requests
from dotenv import load_dotenv
from simple_salesforce import Salesforce, SalesforceMalformedRequest
from tenacity import retry, stop_after_attempt, wait_exponential_jitter, retry_if_exception_type

# ---------------------------------------------------------------------------
# Configuration & Logging
# ---------------------------------------------------------------------------

load_dotenv()
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=LOG_LEVEL,
    format="%(asctime)s [%(levelname)s] %(name)s – %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("sf_meta_sync")

# Salesforce creds
SF_USERNAME = os.getenv("SF_USERNAME")
SF_PASSWORD = os.getenv("SF_PASSWORD")
SF_SECURITY_TOKEN = os.getenv("SF_SECURITY_TOKEN")
SF_DOMAIN = os.getenv("SF_DOMAIN", "login")

# Custom field API names
SF_APPROVAL_FIELD = os.getenv("SF_APPROVAL_FIELD", "Good_Approved__c")
SF_EXPORTED_FIELD = os.getenv("SF_EXPORTED_FIELD", "MetaExported__c")

# Meta creds / IDs
META_ACCESS_TOKEN = os.getenv("META_ACCESS_TOKEN")
META_AD_ACCOUNT_ID = os.getenv("META_AD_ACCOUNT_ID")  # act_123...
META_CUSTOM_AUDIENCE_ID = os.getenv("META_CUSTOM_AUDIENCE_ID")
META_PIXEL_ID = os.getenv("META_PIXEL_ID")
META_DESTINATION = os.getenv("META_DESTINATION", "AUDIENCE").upper()  # AUDIENCE or CONVERSIONS

# Other settings
SYNC_WINDOW_MINUTES = int(os.getenv("SYNC_WINDOW_MINUTES", "10"))
LAST_RUN_FILE = Path("last_run.iso")

# Sanity checks
req = [
    ("SF_USERNAME", SF_USERNAME),
    ("SF_PASSWORD", SF_PASSWORD),
    ("SF_SECURITY_TOKEN", SF_SECURITY_TOKEN),
    ("META_ACCESS_TOKEN", META_ACCESS_TOKEN),
]
if META_DESTINATION == "AUDIENCE":
    req += [("META_CUSTOM_AUDIENCE_ID", META_CUSTOM_AUDIENCE_ID)]
else:
    req += [("META_PIXEL_ID", META_PIXEL_ID)]
missing = [k for k, v in req if not v]
if missing:
    logger.error("Missing env vars: %s", ", ".join(missing))
    sys.exit(1)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def get_salesforce_client() -> Salesforce:
    return Salesforce(
        username=SF_USERNAME,
        password=SF_PASSWORD,
        security_token=SF_SECURITY_TOKEN,
        domain=SF_DOMAIN,
    )


def sha256_hash(s: str) -> str:
    return hashlib.sha256(s.strip().lower().encode("utf-8")).hexdigest()


def get_run_window() -> datetime:
    if LAST_RUN_FILE.exists():
        return datetime.fromisoformat(LAST_RUN_FILE.read_text())
    return datetime.now(timezone.utc) - timedelta(minutes=SYNC_WINDOW_MINUTES)


def update_run_cursor():
    LAST_RUN_FILE.write_text(datetime.now(timezone.utc).isoformat())


@retry(stop=stop_after_attempt(5), wait=wait_exponential_jitter())
def fetch_approved_leads(sf: Salesforce, since_ts: datetime) -> List[Dict[str, str]]:
    logger.info("Fetching approved leads from Salesforce …")
    soql = (
        f"SELECT Id, Email FROM Lead WHERE Email != null "
        f"AND {SF_APPROVAL_FIELD} = true AND {SF_EXPORTED_FIELD} = false "
        f"AND CreatedDate >= {since_ts.strftime('%Y-%m-%dT%H:%M:%SZ')}"
    )
    recs = sf.query_all(soql)["records"]
    logger.info("Found %d approved leads", len(recs))
    return recs


@retry(stop=stop_after_attempt(5), wait=wait_exponential_jitter())
def mark_leads_exported(sf: Salesforce, lead_ids: List[str]):
    if not lead_ids:
        return
    logger.info("Marking %d leads as exported", len(lead_ids))
    batches = [lead_ids[i : i + 200] for i in range(0, len(lead_ids), 200)]
    for batch in batches:
        data = [{"Id": lid, SF_EXPORTED_FIELD: True} for lid in batch]
        sf.bulk.Lead.update(data)


@retry(stop=stop_after_attempt(5), wait=wait_exponential_jitter())
def upload_to_meta(hashed_emails: List[str]):
    logger.info("Uploading %d leads to Meta (%s)…", len(hashed_emails), META_DESTINATION)
    if META_DESTINATION == "AUDIENCE":
        url = f"https://graph.facebook.com/v22.0/{META_CUSTOM_AUDIENCE_ID}/users"
        payload = {
            "payload": json.dumps({"schema": "EMAIL_SHA256", "data": hashed_emails})
        }
    else:  # CONVERSIONS API
        url = "https://graph.facebook.com/v22.0/{pixel_id}/events".format(pixel_id=META_PIXEL_ID)
        payload = json.dumps(
            {
                "data": [
                    {
                        "event_name": "LeadApproved",
                        "event_time": int(datetime.now().timestamp()),
                        "action_source": "crm",
                        "user_data": {"em": hashed_emails},
                    }
                ]
            }
        )
    params = {"access_token": META_ACCESS_TOKEN}
    r = requests.post(url, data=payload, params=params, timeout=30)
    if r.status_code >= 400:
        logger.error("Meta API error: %s %s", r.status_code, r.text)
        r.raise_for_status()


# ---------------------------------------------------------------------------
# Main flow
# ---------------------------------------------------------------------------

def main():
    window_start = get_run_window()
    sf = get_salesforce_client()

    leads = fetch_approved_leads(sf, window_start)
    if not leads:
        logger.info("No new approved leads – exiting.")
        update_run_cursor()
        return

    emails = [l["Email"] for l in leads if l.get("Email")]
    hashed = list({sha256_hash(e) for e in emails})  # uniq

    upload_to_meta(hashed)
    mark_leads_exported(sf, [l["Id"] for l in leads])

    update_run_cursor()
    logger.info("Sync complete.")


if __name__ == "__main__":
    try:
        main()
    except Exception:
        logger.exception("Fatal error – exiting 1")
        sys.exit(1)
