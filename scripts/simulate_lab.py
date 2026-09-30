"""Manual simulation lab runner.

Starts the fake-service lab on 127.0.0.1 and prints the service table so you
can point the platform at it by hand:

    python scripts/simulate_lab.py
    # then, in another terminal:
    python -m agent.discovery --scope <scope-allowing-127.0.0.1> --ports <ports>

Loopback-only. Ctrl-C to stop.
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from common.logging_setup import configure_logging
from sim import SimulatedLab


def main() -> int:
    configure_logging()
    with SimulatedLab() as lab:
        print("Simulated lab running on 127.0.0.1 (loopback only):")
        for name, port in lab.ports.items():
            print(f"  {name:10s} -> 127.0.0.1:{port}")
        print("\nPress Ctrl-C to stop.")
        try:
            import time
            while True:
                time.sleep(3600)
        except KeyboardInterrupt:
            pass
    print("Lab stopped.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
