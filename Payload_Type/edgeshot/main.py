#!/usr/bin/env python3
from mythic_container.mythic_service import start_and_run_forever

# Importing `edgeshot` runs edgeshot/__init__.py, which imports builder.py
# (EdgeShotAgent) and every command module. At startup, mythic_container
# discovers these classes via __subclasses__() and syncs them with the server.
import edgeshot  # noqa: F401


if __name__ == "__main__":
    start_and_run_forever()
