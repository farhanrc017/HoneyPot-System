#!/usr/bin/env python3
"""
HoneyTrap Configuration Helper
Run this once to set up your Telegram bot token and chat ID.
"""
import os, json, subprocess, sys

CONFIG_FILE = os.path.join(os.path.dirname(__file__), ".env")

def main():
    print("=" * 55)
    print("  🍯 HoneyTrap — First-time Setup")
    print("=" * 55)
    print()
    print("To get Telegram alerts you need:")
    print("  1. Create a bot via @BotFather on Telegram → get TOKEN")
    print("  2. Send any message to your bot")
    print("  3. Visit: https://api.telegram.org/bot<TOKEN>/getUpdates")
    print("     to find your CHAT_ID")
    print()

    token   = input("Enter Telegram Bot Token (or press Enter to skip): ").strip()
    chat_id = input("Enter Telegram Chat ID   (or press Enter to skip): ").strip()

    with open(CONFIG_FILE, "w") as f:
        f.write(f"TELEGRAM_BOT_TOKEN={token}\n")
        f.write(f"TELEGRAM_CHAT_ID={chat_id}\n")

    print()
    print(f"✅  Config saved to {CONFIG_FILE}")
    print()
    print("To start HoneyTrap:")
    print()
    print("  # Load env vars, then run:")
    print("  export $(cat .env | xargs)")
    print("  python run.py")
    print()
    print("Or on Windows:")
    print("  set TELEGRAM_BOT_TOKEN=<token>")
    print("  set TELEGRAM_CHAT_ID=<chatid>")
    print("  python run.py")
    print()
    print("Dashboard → http://localhost:5000")

if __name__ == "__main__":
    main()