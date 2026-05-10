from apscheduler.schedulers.background import BackgroundScheduler
from datetime import datetime, timedelta, timezone


def auto_rotate_expired_keys():
    """Rotate any active key that has exceeded its rotation_days."""
    from app.database import SessionLocal
    from app.crypto.core import CryptoCore
    from app.kms.key_manager import KeyManager
    from app.models.key import Key

    db = SessionLocal()
    try:
        active_keys = db.query(Key).filter(Key.state == "enabled").all()
        kms = KeyManager(CryptoCore())
        rotated = 0

        for key in active_keys:
            if not key.rotation_days or not key.created_at:
                continue
            expiry = key.created_at + timedelta(days=key.rotation_days)
            if expiry.tzinfo is None:
                expiry = expiry.replace(tzinfo=timezone.utc)
            if datetime.now(timezone.utc) >= expiry:
                print(f"[scheduler] Rotating key id={key.id} name={key.name}")
                try:
                    kms.rotate_key(db, key.id, "system-scheduler")
                    rotated += 1
                except Exception as exc:
                    print(f"[scheduler] Failed to rotate {key.id}: {exc}")

        print(f"[scheduler] Done — {rotated} key(s) rotated")
    except Exception as exc:
        print(f"[scheduler] Unexpected error: {exc}")
    finally:
        db.close()


def start_scheduler() -> BackgroundScheduler:
    scheduler = BackgroundScheduler(timezone="UTC")
    scheduler.add_job(
        auto_rotate_expired_keys,
        trigger="interval",
        hours=1,
        id="auto_rotate_keys",
        replace_existing=True,
    )
    scheduler.start()
    print("[scheduler] Auto-rotation scheduler started — runs every hour")
    return scheduler
