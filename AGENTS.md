# Repository Guidelines

## Project Structure & Module Organization
- `docker_updater.py`: Main service logic (Docker, registry auth, updates, logging).
- `requirements.txt`: Python dependencies.
- `install.sh` / `uninstall.sh`: Install/uninstall as a systemd-managed service.
- `docker-updater.service`, `docker-updater-sudoers`: Service unit and sudo rules used by the installer.
- `.env.example`, `updater_config.json`: Configuration templates; copy and edit for your environment.
- `README.md`: Unified feature docs and setup guide.
- Runtime paths: `/etc/docker-auto-updater/*.json,.env`, `/var/lib/docker-auto-updater/updater_state.json`, `/var/log/docker-auto-updater/docker_updater.log`.

## Build, Test, and Development Commands
- Setup env: `python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt`.
- Run locally: `CONFIG_FILE=./updater_config.json LOG_LEVEL=DEBUG python3 docker_updater.py`.
- Install service: `sudo ./install.sh && sudo systemctl status docker-updater`.
- View logs: `journalctl -u docker-updater -f` or `tail -f /var/log/docker-auto-updater/docker_updater.log`.

## Coding Style & Naming Conventions
- Python (PEP 8), 4-space indentation, limit lines to ~100 chars.
- `snake_case` for functions/variables, `CamelCase` for classes, env vars in `UPPER_SNAKE_CASE`.
- Prefer type hints and docstrings for public functions/classes.
- Use the `logging` module (no `print`); keep messages actionable.
- No enforced formatter in repo; if used, apply Black defaults before commits.

## Testing Guidelines
- No bundled test suite yet. For contributions, add `pytest` tests under `tests/` for pure helpers (e.g., `parse_semver`, `compare_semver`). Run with `pytest -q`.
- For manual checks, set a small `check_interval` in `updater_config.json`, point `CONFIG_FILE` to it, and run locally while observing logs. Test against a disposable compose project to avoid disrupting production services.

## Commit & Pull Request Guidelines
- Commit style: prefer Conventional Commits (`feat:`, `fix:`, `chore:`, `docs:`). Keep messages imperative and scoped.
- PRs must include: clear description, motivation, before/after behavior, local verification steps (commands/logs), and any config or path changes. Update docs when behavior changes (`README.md`).

## Security & Configuration Tips
- Do not commit secrets. Use `.env` outside version control; start from `.env.example`.
- Principle of least privilege: restrict registry creds; rotate regularly.
- Validate JSON configs before deploy: `python -m json.tool updater_config.json`.
