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

    Synchronizes with ``"fetch"``: the objects the session already holds take
    the new values only for the rows the database actually matched, so a
    stale object is never marked updated by a statement that changed nothing.
    ``"auto"`` would fall back to it anyway wherever the WHERE carries an
    EXISTS the ORM cannot evaluate in Python, and would otherwise evaluate in
    Python, against the stale state.

    Flushing stays with the caller: production sessions have ``autoflush``
    off, and ``soft_delete`` orders its flushes around the unique index.
    ``AsyncSession.execute`` is typed as ``Result[Any]``; the narrowing to a
    cursor lives here.
    """
    result = await session.execute(stmt.execution_options(synchronize_session="fetch"))
    assert isinstance(result, CursorResult)
    return result.rowcount
