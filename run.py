#!/usr/bin/env python3
"""
HoneyTrap v2 — Single launcher
Starts all honeypot listeners + Flask dashboard together
"""
import threading, os, sys, logging

os.makedirs(os.path.join(os.path.dirname(__file__), "logs"), exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(os.path.join(os.path.dirname(__file__), "logs", "honeypot.log")),
        logging.StreamHandler()
    ]
)
log = logging.getLogger("honeytrap")

import honeypot
import dashboard

def main():
    log.info("=" * 55)
    log.info("  HoneyTrap v2 — Advanced Honeypot System")
    log.info("=" * 55)

    honeypot.init_db()

    for port, service in honeypot.HONEYPOT_PORTS.items():
        t = threading.Thread(
            target=honeypot.start_listener,
            args=(port, service),
            daemon=True
        )
        t.start()

    log.info(f"[*] {len(honeypot.HONEYPOT_PORTS)} honeypot listeners started")
    log.info("[*] Dashboard → http://0.0.0.0:5000")
    log.info("[*] Press Ctrl+C to stop")

    dashboard.app.run(host="0.0.0.0", port=5000, debug=False, use_reloader=False)

if __name__ == "__main__":
    main()