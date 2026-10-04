"""add_threat_feed_state_and_generation_id

Revision ID: b4a49925f0e5
Revises: 
Create Date: 2026-10-04 16:27:17.946010

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'b4a49925f0e5'
down_revision: Union[str, Sequence[str], None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema to add generation_id on threat_indicators and threat_feed_states table."""
    conn = op.get_bind()
    inspector = sa.inspect(conn)

    # 1. Add generation_id to threat_indicators if not present
    if "threat_indicators" in inspector.get_table_names():
        columns = [c["name"] for c in inspector.get_columns("threat_indicators")]
        if "generation_id" not in columns:
            op.add_column("threat_indicators", sa.Column("generation_id", sa.String(36), nullable=True))
            op.create_index("ix_threat_indicators_generation_id", "threat_indicators", ["generation_id"])

    # 2. Create threat_feed_states if not present
    if "threat_feed_states" not in inspector.get_table_names():
        op.create_table(
            "threat_feed_states",
            sa.Column("source", sa.String(64), primary_key=True),
            sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.text("1")),
            sa.Column("status", sa.String(32), nullable=False, server_default="idle"),
            sa.Column("freshness", sa.String(32), nullable=False, server_default="never_synced"),
            sa.Column("last_success_at", sa.String(32), nullable=True),
            sa.Column("last_attempt_at", sa.String(32), nullable=True),
            sa.Column("last_success_count", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("last_error", sa.String(256), nullable=True),
            sa.Column("etag", sa.String(128), nullable=True),
            sa.Column("last_modified", sa.String(128), nullable=True),
            sa.Column("current_generation_id", sa.String(36), nullable=True),
            sa.Column("refresh_interval_seconds", sa.Integer(), nullable=False, server_default="86400"),
            sa.Column("updated_at", sa.String(32), nullable=False),
        )


def downgrade() -> None:
    """Downgrade schema."""
    conn = op.get_bind()
    inspector = sa.inspect(conn)
    if "threat_feed_states" in inspector.get_table_names():
        op.drop_table("threat_feed_states")
    if "threat_indicators" in inspector.get_table_names():
        columns = [c["name"] for c in inspector.get_columns("threat_indicators")]
        if "generation_id" in columns:
            op.drop_index("ix_threat_indicators_generation_id", table_name="threat_indicators")
            op.drop_column("threat_indicators", "generation_id")
