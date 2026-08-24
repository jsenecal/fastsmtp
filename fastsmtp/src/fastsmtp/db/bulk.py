"""Bulk UPDATEs whose row count is the answer.

The soft-delete cascades (``db.soft_delete``) and the delivery-queue writers
(``webhook.queue``) both decide something from how many rows a guarded UPDATE
matched: a restore that brought back N recipients, a cancel that landed under
us, a retry that was blocked. This module holds that one block so neither of
them spells it out. It lives on its own because ``soft_delete`` imports the
queue, so the queue cannot import ``soft_delete``.
"""

from sqlalchemy import CursorResult, Update
from sqlalchemy.ext.asyncio import AsyncSession


async def execute_counted(session: AsyncSession, stmt: Update) -> int:
    """Run an ORM-enabled UPDATE and return how many rows it matched.

    Synchronizes with ``"fetch"``: only the objects the session holds for
    rows the database actually matched are touched, so a stale object is
    never marked updated by a statement that changed nothing. On those
    objects the SET's literal values are applied, and every column the
    database computed instead is *expired* - ``updated_at`` through its
    ``onupdate`` whenever the SET does not name it. An expired attribute is
    loaded on its next read, which from async code raises ``MissingGreenlet``;
    so every UPDATE routed here assigns ``updated_at`` itself. ``"auto"``
    would fall back to "fetch" anyway wherever the WHERE carries an EXISTS
    the ORM cannot evaluate in Python, and would otherwise evaluate in
    Python, against the stale state.

    Flushing stays with the caller: production sessions have ``autoflush``
    off, and ``soft_delete`` orders its flushes around the unique index.
    ``AsyncSession.execute`` is typed as ``Result[Any]``; the narrowing to a
    cursor lives here.
    """
    result = await session.execute(stmt.execution_options(synchronize_session="fetch"))
    assert isinstance(result, CursorResult)
    return result.rowcount
