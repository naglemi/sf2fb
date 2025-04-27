# Lead Manager – Zero‑Zapier Meta ↔ Salesforce Pipeline

Welcome! 👋
This guide walks **complete beginners** through setting up and running the **one‑file** `lead_manager.py` script that:

1. **Catches Facebook/Instagram Lead‑Ad submissions** in real time and creates a Lead in Salesforce.
2. Lets a person mark each lead as **Good (G)** in a spreadsheet.
3. Sends only the good leads back to Meta so your ads can find more people like them.

No prior Python or command‑line experience needed—just follow the steps.

---
## ️Prerequisites
| What you need | Why | Quick link |
|--------------|-----|------------|
| **Salesforce** account with API access (Enterprise, Unlimited, or dev org) | Stores your leads | – |
| **Facebook/Meta Business Manager** account | Owns your Facebook Page & Ads | – |
| **Python 3.10 or later** installed | Runs the script | [python.org/downloads](https://www.python.org/downloads) |
| A place to run the script 24 / 7 (optional) | e.g. Heroku, Fly.io, AWS, Render | – |

> **Tip for Windows users:** If you’ve never installed Python, grab the official Windows installer, tick “Add Python to PATH,” then click *Next* until it finishes.

---
## 1. Download the project
1. Click the **▼ Code** button in GitHub (or get the ZIP your friend sent).  
2. Extract the folder to your Desktop or any convenient place.

You should see:
```
lead_manager.py   ← our all‑in‑one script
README.md         ← (this file)
requirements.txt  ← list of packages
```

---
## 2. Collect your secrets & create `.env`
Create a plain‑text file called **`.env`** in the project folder.
Each line is `KEY=value` (no quotes). Example:
```env
# -------------- SALESFORCE --------------
SF_USERNAME=you@example.com
SF_PASSWORD=SuperSecret123
SF_SECURITY_TOKEN=00x5AB…
SF_DOMAIN=login          # leave as login unless using a sandbox

# -------------- META (outbound) --------------
META_ACCESS_TOKEN=EAABsbCS1iHgBA…
META_DESTINATION=AUDIENCE             # or CONVERSIONS
META_CUSTOM_AUDIENCE_ID=987654321098765
META_PIXEL_ID=123456789098765         # only if using CONVERSIONS

# -------------- META (webhook) --------------
META_PAGE_TOKEN=EAADfZC…         # Page access token (long‑lived)
META_VERIFY_TOKEN=PickAStrongRandomString
META_APP_SECRET=your‑fb‑app‑secret

# -------------- GENERAL --------------
LOG_LEVEL=INFO
SYNC_WINDOW_MINUTES=10
```

### Where do I get each value?
| Variable | How to find it |
|----------|----------------|
| **SF_SECURITY_TOKEN** | In Salesforce: *Setup → User Settings → Reset My Security Token* ([help.salesforce.com](https://help.salesforce.com/s/articleView?id=sf.remoteaccess_access_tokens.htm&language=en_US&type=5&utm_source=chatgpt.com)) |
| **META_PAGE_TOKEN**   | In the *Meta App Dashboard*: *Products → Facebook Login → Access Tokens → Generate Long‑Lived Page Token* (convert short‑lived → long‑lived) ([developers.facebook.com](https://developers.facebook.com/docs/facebook-login/guides/access-tokens/get-long-lived/?utm_source=chatgpt.com), [developers.facebook.com](https://developers.facebook.com/docs/facebook-login/guides/access-tokens/?utm_source=chatgpt.com)) |
| **META_APP_SECRET**   | *App Dashboard → Settings → Basic* |
| **META_CUSTOM_AUDIENCE_ID** | In Ads Manager: *Audiences → click the audience → see ID in URL* |
| **META_PIXEL_ID** | *Events Manager → your Pixel → Settings → Pixel ID* |

If a value isn’t needed for your use case (e.g. `META_PIXEL_ID` when using AUDIENCE mode), you can leave it blank.

---
## 3 Run the webhook locally (test mode)
```bash
python lead_manager.py webhook --port 5000
```
You should see:
```
Starting webhook server on 0.0.0.0:5000
 * Running on http://0.0.0.0:5000/ (Press CTRL+C to quit)
```

### Expose it to Facebook
Meta needs a **public** HTTPS URL. The quickest way is with **ngrok**:
```bash
ngrok http 5000
```
Copy the `https://random-id.ngrok.io` URL.

#### Configure the Webhook in Meta
1. Go to *developers.facebook.com* → *App* → **Webhooks**.  
2. Choose **Page** → *Leads*.  
3. Enter your ngrok URL + `/webhook` (e.g. `https://random-id.ngrok.io/webhook`) and your `META_VERIFY_TOKEN`.  
4. Click **Verify and Save**.

If everything’s right, Meta flashes “Subscribed.”

> **Pro tip:** For production, deploy to **Fly.io**, **Render**, **Cloud Run**, or **AWS Lambda + Function URL** so it’s always online.

---
## 4. Export leads for review
Once leads start flowing into Salesforce, ask the script to create a spreadsheet:
```bash
python lead_manager.py export_sheet --out leads_to_review.csv
```
Open the CSV in Excel or Google Sheets and type **`G`** in the **GoodFlag** column for each lead that looks legit.

---
## 5. Import the reviewed sheet and sync the good leads
```bash
python lead_manager.py import_sheet --in leads_to_review.csv
```
The script:
1. Marks every `GoodFlag = G` row as approved in Salesforce.  
2. Immediately runs the **sync** job, which uploads those leads to Meta.

You’ll see “Uploading N approved leads to Meta…” in the console.

---
## 6. (Automation) Schedule the jobs
| Task | Suggested cadence | How to |
|------|-------------------|--------|
| `webhook` | 24 / 7 | Deployed as a web service (Heroku dyno, Fly.io app, etc.) |
| `sync` | every 5–15 min | **GitHub Actions** cron, **Linux cron**, or **Windows Task Scheduler** |
| `export_sheet` | daily | Same schedulers as above; emails the CSV via Outlook/SendGrid if desired |

Example cron entry (Linux):
```cron
*/10 * * * * /usr/bin/python /home/ubuntu/lead_manager.py sync >> /var/log/leadsync.log 2>&1
```

---
## Troubleshooting
| Symptom | Likely cause & fix |
|---------|-------------------|
| *Webhook returns 403* | `META_VERIFY_TOKEN` mismatch or signature check failed. Double‑check both in `.env` and Meta Dashboard. |
| *“Missing env vars” error* | You forgot a key in `.env` or mis‑spelled it. |
| *Meta uploads fail (400 error)* | Wrong **Custom Audience ID** or **Pixel ID**, or your token lacks `ads_management`. |
| *Salesforce API login fails* | Password expired, wrong security token, or profile lacks API Enabled. |

---
## FAQ
**Q – Can I run everything on Windows?**  
A – Yes. Use PowerShell instead of bash: replace `export VAR=value` with `$Env:VAR = "value"`.

**Q – Why do I have to refresh Meta tokens?**  
A – Long‑lived Page tokens last ~60 days. Set a calendar reminder to generate a new one. More on token lifecycles in Meta docs. ([developers.facebook.com](https://developers.facebook.com/docs/facebook-login/guides/access-tokens/get-long-lived/?utm_source=chatgpt.com))

**Q – Do I need a paid Salesforce edition?**  
A – Any edition with **API access** (Enterprise, Unlimited, Professional + API add‑on, or a free Developer org) works.

---
## Next steps
* 🌐 **Deploy** the webhook permanently (Render, Fly.io, etc.).  
* 🔒 Rotate your Meta & Salesforce secrets regularly.  
* 📊 Add reporting (e.g. push results to Google Sheets or Slack) – you can extend the script; it’s only ~300 lines.

Happy lead‑syncing! 🎉

