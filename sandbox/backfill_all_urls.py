"""One-time backfill: scan ALL historical events (not just going forward from
the watermark) for embedded URLs using fetcher's own widened _extract_urls,
and process each one through the normal _process_url pipeline. Reads directly
from the DB rather than paginating the HTTP API since this runs on the same
host and is a one-shot bulk scan, not the steady-state poll loop."""
import sqlite3

import fetcher

conn = sqlite3.connect('data/honeypot.db')
conn.row_factory = sqlite3.Row

BATCH = 2000
last_id = 0
total_scanned = 0
total_urls_found = 0
unique_urls = set()

while True:
    rows = conn.execute(
        "SELECT id, ip, event_type, data FROM events WHERE id > ? ORDER BY id ASC LIMIT ?",
        (last_id, BATCH),
    ).fetchall()
    if not rows:
        break
    for row in rows:
        event = dict(row)
        urls = fetcher._extract_urls(event)
        for url in urls:
            total_urls_found += 1
            unique_urls.add(url)
            fetcher._process_url(url, event)
        last_id = event["id"]
    total_scanned += len(rows)
    print(f"[backfill] scanned {total_scanned} events (up to id={last_id}), "
          f"{total_urls_found} url refs, {len(unique_urls)} unique so far")

conn.close()
print(f"[backfill] DONE: scanned {total_scanned} events, "
      f"{total_urls_found} url references, {len(unique_urls)} unique URLs processed")
