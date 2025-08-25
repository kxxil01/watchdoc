import json
import os


def notify_event(event_type: str, payload: dict, logger) -> None:
    url = os.getenv('WEBHOOK_URL')
    if not url:
        return
    try:
        import requests  # lazy import

        headers = {'Content-Type': 'application/json'}
        data = json.dumps({'event': event_type, **payload})
        requests.post(url, headers=headers, data=data, timeout=5)
    except Exception as e:
        logger.warning(f"Webhook notify failed: {e}")

