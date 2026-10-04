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
    """Upgrade schema: assign legacy generations, create threat_feed_states, and establish generation-aware uniqueness."""
    conn = op.get_bind()
    inspector = sa.inspect(conn)
    now_iso = sa.func.datetime('now')

    # 1. Create threat_feed_states table first if missing
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

    # 2. Upgrade threat_indicators if present
    if "threat_indicators" in inspector.get_table_names():
        columns = [c["name"] for c in inspector.get_columns("threat_indicators")]
        if "generation_id" not in columns:
            op.add_column("threat_indicators", sa.Column("generation_id", sa.String(36), nullable=True))

        # Assign deterministic legacy generation IDs to legacy records with generation_id IS NULL
        res = conn.execute(sa.text("SELECT DISTINCT source FROM threat_indicators WHERE generation_id IS NULL OR generation_id = ''")).fetchall()
        for row in res:
            src = row[0]
            if src:
                legacy_gen = f"legacy-gen-{src}"
                conn.execute(
                    sa.text("UPDATE threat_indicators SET generation_id = :gen WHERE source = :src AND (generation_id IS NULL OR generation_id = '')"),
                    {"gen": legacy_gen, "src": src}
                )
                cnt = conn.execute(sa.text("SELECT COUNT(*) FROM threat_indicators WHERE source = :src AND generation_id = :gen"), {"src": src, "gen": legacy_gen}).scalar() or 0
                
                # Ensure ThreatFeedState exists with current_generation_id = legacy_gen and freshness = 'stale'
                st = conn.execute(sa.text("SELECT source FROM threat_feed_states WHERE source = :src"), {"src": src}).fetchone()
                if not st:
                    conn.execute(
                        sa.text("""
                            INSERT INTO threat_feed_states (source, enabled, status, freshness, last_success_count, current_generation_id, refresh_interval_seconds, updated_at)
                            VALUES (:src, 1, 'idle', 'stale', :cnt, :gen, 86400, datetime('now'))
                        """),
                        {"src": src, "cnt": cnt, "gen": legacy_gen}
                    )

        # Batch recreate table to replace old UNIQUE(source, indicator_type, indicator_hash)
        # with new UNIQUE(source, generation_id, indicator_type, indicator_hash)
        with op.batch_alter_table("threat_indicators", recreate="always") as batch_op:
            batch_op.create_unique_constraint(
                "uq_source_gen_type_indicator",
                ["source", "generation_id", "indicator_type", "indicator_hash"]
            )
            batch_op.create_index("ix_threat_indicators_generation_id", ["generation_id"])
            batch_op.create_index("ix_threat_indicators_indicator_hash", ["indicator_hash"])
            batch_op.create_index("ix_threat_indicators_source", ["source"])


def downgrade() -> None:
    """Downgrade schema."""
    conn = op.get_bind()
    inspector = sa.inspect(conn)
    if "threat_feed_states" in inspector.get_table_names():
        op.drop_table("threat_feed_states")
    if "threat_indicators" in inspector.get_table_names():
        with op.batch_alter_table("threat_indicators", recreate="always") as batch_op:
            batch_op.drop_constraint("uq_source_gen_type_indicator", type_="unique")
            batch_op.drop_index("ix_threat_indicators_generation_id")
            batch_op.drop_column("generation_id")
            batch_op.create_unique_constraint("uq_source_type_indicator", ["source", "indicator_type", "indicator_hash"])
