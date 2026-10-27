"""``python -m gwops`` — run the PID-1 supervisor."""

import asyncio

from gwops.supervisor.main import main

if __name__ == "__main__":
    asyncio.run(main())
