"""Main entry point for the IaC Audit Pack MCP Server Actor."""

import asyncio

from .main import main

if __name__ == '__main__':
    asyncio.run(main())
