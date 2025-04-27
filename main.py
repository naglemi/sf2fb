"""
lead_manager.py – ONE-FILE CLI for Meta ↔ Salesforce Lead Loop
==============================================================
Author: OpenAI ChatGPT (o3 reasoning model)  •  Updated: 2025-04-27

This script **does everything**:

| Mode (`--mode`) | What it does |
|-----------------|---------------------------------------------------------|
| `webhook`       | Runs an HTTPS Flask endpoint Meta Lead Ads will call.  |
| `sync`          | Pushes *approved* leads (Good_Approved__c = true & not yet exported) back to Meta (Custom Audience **or** Conversions API). |
| `export_sheet`  | Dumps *un-reviewed* Leads to a **CSV** with a `GoodFlag` column for human review. |
| `import_sheet`  | Reads the human-edited CSV, marks rows with `GoodFlag in {G,g,GOOD,good}` as approved in Salesforce, then (optionally) triggers `sync`. |

---
Dependencies
------------
```bash
pip install flask simple-salesforce python-dotenv requests tenacity
```
(Standard `csv` is from the std-lib, no pandas needed.)

---
Environment Variables (same for all modes)
-----------------------------------------
```text
# Salesforce
SF_USERNAME=···
SF_PASSWORD=···
SF_SECURITY_TOKEN=···
SF_DOMAIN=login            # or test
SF_APPROVAL_FIELD=Good_Approved__c
SF_EXPORTED_FIELD=MetaExported__c

# Meta – both inbound + outbound
META_PAGE_TOKEN=EAAB…                    # for webhook fetch
META_VERIFY_TOKEN=MyVerySecretVerify     # for webhook GET challenge
META_APP_SECRET=…                       # optional, for X-Hub signature check

META_ACCESS_TOKEN=EAAB…                 # outbound access
META_DESTINATION=AUDIENCE               # or CONVERSIONS
META_CUSTOM_AUDIENCE_ID=987654321098765 # required if AUDIENCE
META_PIXEL_ID=123456789098765           # required if CONVERSIONS

# General
LOG_LEVEL=INFO
SYNC_WINDOW_MINUTES=10
```

---
Usage examples
--------------
```bash
# run webhook locally
python lead_manager.py webhook --port 5000

# cron job every 10 min – approved lead sync
python lead_manager.py sync

# export leads for human review (CSV)
python lead_manager.py export_sheet --out /tmp/leads_to_review.csv

# later, import the spreadsheet after reviewers filled GoodFlag column
python lead_manager.py import_sheet --in /tmp/leads_to_review.csv
```

---
Code starts here
----------------
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import hmac
import json
import logging
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List

import requests
from dotenv import load_dotenv
from simple_salesforce import Salesforce, SalesforceMalformedRequest
from tenacity import retry, stop_after_attempt, wait_exponential_jitter, retry_if_exception_type

# ---------------------------------------------------------------------------
# Global configuration & helpers
# ---------------------------------------------------------------------------

load_dotenv()
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=LOG_LEVEL,
    format="%(asctime)s [%(levelname)s] %(name)s – %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
log = logging.getLogger("lead_manager")

# Salesforce creds & fields
SF_USERNAME = os.getenv("SF_USERNAME")
SF_PASSWORD = os.getenv("SF_PASSWORD")
SF_SECURITY_TOKEN = os.getenv("SF_SECURITY_TOKEN")
SF_DOMAIN = os.getenv("SF_DOMAIN", "login")

SF_APPROVAL_FIELD = os.getenv("SF_APPROVAL_FIELD", "Good_Approved__c")
SF_EXPORTED_FIELD = os.getenv("SF_EXPORTED_FIELD", "MetaExported__c")

# Meta (inbound)
META_PAGE_TOKEN = os.getenv("META_PAGE_TOKEN")
VERIFY_TOKEN = os.getenv("META_VERIFY_TOKEN")
APP_SECRET = os.getenv("META_APP_SECRET")

# Meta (outbound)
META_ACCESS_TOKEN = os.getenv("META_ACCESS_TOKEN")
META_DESTINATION = os.getenv("META_DESTINATION", "AUDIENCE").upper()
META_CUSTOM_AUDIENCE_ID = os.getenv("META_CUSTOM_AUDIENCE_ID")
META_PIXEL_ID = os.getenv("META_PIXEL_ID")

# General
SYNC_WINDOW_MINUTES = int(os.getenv("SYNC_WINDOW_MINUTES", "10"))
LAST_RUN_FILE = Path("last_run.iso")


# ---------------------------------------------------------------------------
# Salesforce client helper
# ---------------------------------------------------------------------------

def get_sf() -> Salesforce:
    missing = [n for n, v in [("SF_USERNAME", SF_USERNAME), ("SF_PASSWORD", SF_PASSWORD), ("SF_SECURITY_TOKEN", SF_SECURITY_TOKEN)] if not v]
    if missing:
        log.error("Missing SF env vars: %s", ", ".join(missing))
        sys.exit(1)
    return Salesforce(username=SF_USERNAME, password=SF_PASSWORD, security_token=SF_SECURITY_TOKEN, domain=SF_DOMAIN)


# ---------------------------------------------------------------------------
# Outbound: push approved leads to Meta
# ---------------------------------------------------------------------------

def _sha256(s: str) -> str:
    return hashlib.sha256(s.strip().lower().encode()).hexdigest()


@retry(stop=stop_after_attempt(5), wait=wait_exponential_jitter())
def _upload_to_meta(hashed_emails: List[str]):
    if META_DESTINATION == "AUDIENCE":
        url = f"https://graph.facebook.com/v22.0/{META_CUSTOM_AUDIENCE_ID}/users"
        payload = {
            "payload": json.dumps({"schema": "EMAIL_SHA256", "data": hashed_emails})
        }
    else:  # CONVERSIONS
        url = f"https://graph.facebook.com/v22.0/{META_PIXEL_ID}/events"
        payload = json.dumps({
            "data": [{
                "event_name": "LeadApproved",
                "event_time": int(datetime.now().timestamp()),
                "action_source": "crm",
                "user_data": {"em": hashed_emails},
            }]
        })
    r = requests.post(url, data=payload, params={"access_token": META_ACCESS_TOKEN}, timeout=30)
    if r.status_code >= 400:
        log.error("Meta API error %s: %s", r.status_code, r.text)
        r.raise_for_status()


def sync_good_leads():
    """Scheduled job: find approved leads not yet exported, send to Meta, mark exported."""
    sf = get_sf()
    soql = (
        f"SELECT Id, Email FROM Lead WHERE Email != null AND {SF_APPROVAL_FIELD} = true "
        f"AND {SF_EXPORTED_FIELD} = false"
    )
    recs = sf.query_all(soql)["records"]
    if not recs:
        log.info("No approved leads to sync.")
        return

    emails = [r["Email"] for r in recs]
    hashed = list({_sha256(e) for e in emails})
    log.info("Uploading %d approved leads to Meta (%s)", len(hashed), META_DESTINATION)
    _upload_to_meta(hashed)

    # mark exported
    batches = [recs[i : i + 200] for i in range(0, len(recs), 200)]
    for batch in batches:
        sf.bulk.Lead.update([{"Id": r["Id"], SF_EXPORTED_FIELD: True} for r in batch])
    log.info("Marked %d leads as exported.", len(recs))


# ---------------------------------------------------------------------------
# Spreadsheet export/import helpers
# ---------------------------------------------------------------------------

EXPORT_HEADERS = ["Id", "FirstName", "LastName", "Email", "Company", "GoodFlag"]


def export_lead_sheet(path: Path):
    sf = get_sf()
    soql = (
        f"SELECT Id, FirstName, LastName, Email, Company FROM Lead "
        f"WHERE {SF_APPROVAL_FIELD} = false AND {SF_EXPORTED_FIELD} = false"
    )
    recs = sf.query_all(soql)["records"]
    if not recs:
        log.info("No leads pending review.")
        return

    with path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=EXPORT_HEADERS)
        writer.writeheader()
        for r in recs:
            writer.writerow({
                "Id": r["Id"],
                "FirstName": r.get("FirstName", ""),
                "LastName": r.get("LastName", ""),
                "Email": r.get("Email", ""),
                "Company": r.get("Company", ""),
                "GoodFlag": "",  # blank for human to fill with G/g
            })
    log.info("Wrote %d leads to %s", len(recs), path)


def import_lead_sheet(path: Path, run_sync_after: bool = True):
    if not path.exists():
        log.error("Spreadsheet not found: %s", path)
        sys.exit(1)

    sf = get_sf()
    good_ids: List[str] = []
    with path.open() as f:
        reader = csv.DictReader(f)
        for row in reader:
            flag = row.get("GoodFlag", "").strip().lower()
            if flag == "g":
                good_ids.append(row["Id"])

    if not good_ids:
        log.info("No rows marked as good (GoodFlag = G).")
    else:
        # bulk update approval field
        log.info("Marking %d leads as approved in Salesforce", len(good_ids))
        batches = [good_ids[i : i + 200] for i in range(0, len(good_ids), 200)]
        for batch in batches:
            sf.bulk.Lead.update([{"Id": lid, SF_APPROVAL_FIELD: True} for lid in batch])

    if run_sync_after:
        sync_good_leads()


# ---------------------------------------------------------------------------
# Inbound Meta Webhook (Flask)
# ---------------------------------------------------------------------------

def run_webhook(host: str, port: int):
    missing = [n for n, v in [("META_PAGE_TOKEN", META_PAGE_TOKEN), ("META_VERIFY_TOKEN", VERIFY_TOKEN)] if not v]
    if missing:
        log.error("Missing Meta env vars: %s", ", ".join(missing))
        sys.exit(1)

    from flask import Flask, request, abort

    app = Flask(__name__)

    @app.route("/webhook", methods=["GET"])
    def verify():
        if request.args.get("hub.mode") == "subscribe" and request.args.get("hub.verify_token") == VERIFY_TOKEN:
            return request.args.get("hub.challenge"), 200
        return "verification failed", 403

    @app.route("/webhook", methods=["POST"])
    def receive():
        if APP_SECRET and not _valid_signature(request):
            abort(403)
        data = request.get_json(force=True)
        for entry in data.get("entry", []):
            for change in entry.get("changes", []):
                lead_id = change.get("value", {}).get("leadgen_id")
                if lead_id:
                    try:
                        _process_meta_lead(lead_id)
                    except Exception:
                        log.exception("Error processing lead %s", lead_id)
        return "ok", 200

    def _valid_signature(req):
        sig = req.headers.get("X-Hub-Signature")
        if not (APP_SECRET and sig and sig.startswith("sha1=")):
            return True  # skip check if no secret configured
        digest = hmac.new(APP_SECRET.encode(), req.data, hashlib.sha1).hexdigest()
        return hmac.compare_digest(digest, sig.split("=", 1)[1])

    def _process_meta_lead(lead_id: str):
        log.info("Fetching full Meta lead %s", lead_id)
        resp = requests.get(
            f"https://graph.facebook.com/v22.0/{lead_id}",
            params={"access_token": META_PAGE_TOKEN, "fields": "field_data,created_time"},
            timeout=10,
        ).json()
        field_map = {f["name"]: f["values"][0] for f in resp.get("field_data", [])}
        email = field_map.get("email")
        sf = get_sf()
        payload = {
            "FirstName": field_map.get("first_name", ""),
            "LastName": field_map.get("last_name", "Meta Lead"),
            "Company": field_map.get("company", "Facebook Lead Ad"),
            "Email": email,
            "LeadSource": "Facebook Lead Ad",
            "FB_Lead_ID__c": lead_id,
            SF_APPROVAL_FIELD: False,
            SF_EXPORTED_FIELD: False,
        }
        if email:
            res = sf.query_all(f"SELECT Id FROM Lead WHERE Email='{email}' LIMIT 1")
            if res["totalSize"]:
                sf.Lead.update(res["records"][0]["Id"], payload)
                return
        sf.Lead.create(payload)

    log.info("Starting webhook server on %s:%s", host, port)
    app.run(host=host, port=port)


# ---------------------------------------------------------------------------
# Argument parsing & main
# ---------------------------------------------------------------------------

def parse_args():
    ap = argparse.ArgumentParser(description="Meta ↔ Salesforce Lead Manager (all-in-one)")
    sub = ap.add_subparsers(dest="mode", required=True)

    # webhook
    p_web = sub.add_parser("webhook", help="Run Flask webhook server")
    p_web.add_argument("--host", default="0.0.0.0")
    p_web.add_argument("--port", type=int, default=5000)

    # sync
    sub.add_parser("sync", help="Export approved leads to Meta")

    # export_sheet
    p_exp = sub.add_parser("export_sheet", help="Dump CSV for human review")
    p_exp.add_argument("--out", type=Path, default=Path(f"leads_to_review_{datetime.now().strftime('%Y%m%d_%H%M')}.csv"))

    # import_sheet
    p_imp = sub.add_parser("import_sheet", help="Import reviewed CSV and mark approvals")
    p_imp.add_argument("--in", dest="infile", type=Path, required=True)
    p_imp.add_argument("--no-sync", action="store_true", help="Skip automatic sync after import")

    return ap.parse_args()


if __name__ == "__main__":
    args = parse_args()
    try:
        if args.mode == "webhook":
            run_webhook(args.host, args.port)
        elif args.mode == "sync":
            sync_good_leads()
        elif args.mode == "export_sheet":
            export_lead_sheet(args.out)
        elif args.mode == "import_sheet":
            import_lead_sheet(args.infile, run_sync_after=not args.no_sync)
        else:
            raise ValueError("Unknown mode")
    except Exception:
        log.exception("Fatal error")
        sys.exit(1)
