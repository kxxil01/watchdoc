import os

def init_metrics(logger):
    """Initialize Prometheus metrics if configured via env.

    Returns a dict with keys: enabled, updates, rollbacks, failures, state_restored
    """
    try:
        from prometheus_client import Counter, start_http_server  # type: ignore
    except Exception:  # pragma: no cover
        Counter = None
        start_http_server = None

    result = {
        'enabled': False,
        'updates': None,
        'rollbacks': None,
        'failures': None,
        'state_restored': None,
    }
    port = os.getenv('METRICS_PORT')
    if port and start_http_server and Counter:
        try:
            start_http_server(int(port), addr=os.getenv('METRICS_ADDR', '0.0.0.0'))
            result['updates'] = Counter('updater_updates_total', 'Number of updates performed')
            result['rollbacks'] = Counter('updater_rollbacks_total', 'Number of rollbacks performed')
            result['failures'] = Counter('updater_failures_total', 'Number of update failures')
            result['state_restored'] = Counter('updater_state_restored_total', 'State restored from backup')
            result['enabled'] = True
            logger.info(f"Prometheus metrics server on {os.getenv('METRICS_ADDR','0.0.0.0')}:{port}")
        except Exception as e:
            logger.warning(f"Failed to start metrics: {e}")
    return result

