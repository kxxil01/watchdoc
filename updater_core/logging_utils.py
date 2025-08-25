import json
import logging
from datetime import datetime


class JSONFormatter(logging.Formatter):
    def format(self, record):
        payload = {
            'ts': datetime.utcnow().isoformat() + 'Z',
            'level': record.levelname,
            'msg': record.getMessage(),
            'logger': record.name,
        }
        if record.exc_info:
            payload['exc_info'] = self.formatException(record.exc_info)
        return json.dumps(payload)

