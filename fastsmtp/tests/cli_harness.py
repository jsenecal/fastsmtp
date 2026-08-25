"""Helpers shared by the server CLI tests.

The fixtures that use these live in ``conftest.py``, where pytest discovers
them; only the plain class and function live here. They need a module of their
own because ``conftest`` is not importable by name: both test trees have one
(``fastsmtp/tests`` and ``fastsmtp-cli/tests``), pytest puts both directories on
``sys.path``, and ``from conftest import ...`` then resolves to whichever was
imported first - which is the other package as soon as the whole suite runs.
"""

import asyncio
import re
from collections.abc import Awaitable, Callable
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*m")


def strip_ansi(text: str) -> str:
    """Drop colour codes so assertions match on the words, not the styling."""
    return ANSI_ESCAPE.sub("", text)


class Db:
    """Run a coroutine against a fresh session in its own loop and commit.

    The CLI opens its own sessions and drives them with ``asyncio.run``, and an
    asyncpg connection belongs to the loop that opened it, so a test cannot hand
    the CLI the suite's session. This mirrors what the CLI does, against the
    same factory the ``db`` fixture patches in.
    """

    def __init__(self, make_session: Callable[[], AsyncSession]):
        self._make_session = make_session

    def __call__(self, fn: Callable[[AsyncSession], Awaitable[Any]]) -> Any:
        async def go() -> Any:
            async with self._make_session() as session:
                result = await fn(session)
                await session.commit()
                return result

        return asyncio.run(go())
