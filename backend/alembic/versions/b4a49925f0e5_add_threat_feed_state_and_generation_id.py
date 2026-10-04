"""add_threat_feed_state_and_generation_id

Revision ID: b4a49925f0e5
Revises: a1b2c3d4e5f6
Create Date: 2026-10-04 16:27:17.946010

"""
from datetime import datetime, timezone
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'b4a49925f0e5'
down_revision: Union[str, Sequence[str], None] = 'a1b2c3d4e5f6'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema: assign legacy generations, enforce generation_id NOT NULL, reconcile threat_feed_states, and establish generation-aware uniqueness."""
    conn = op.get_bind()
    inspector = sa.inspect(conn)

    # 1. Create threat_feed_states table first if missing
    if "threat_feed_states" not in inspector.get_table_names():
        op.create_table(
            "threat_feed_states",
            sa.Column("source", sa.String(64), primary_key=True),
            # sa.true() renders as a dialect-correct boolean default
            # (1 on SQLite, true on PostgreSQL).
            sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
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

    # 1b. Ensure scan_history columns and indexes are present
    if "scan_history" in inspector.get_table_names():
        scan_cols = [c["name"] for c in inspector.get_columns("scan_history")]
        with op.batch_alter_table("scan_history") as batch_op:
            if "user_id" not in scan_cols:
                batch_op.add_column(sa.Column("user_id", sa.String(), sa.ForeignKey("users.id", name="fk_scan_history_user_id"), nullable=True))
            if "guest_session_hash" not in scan_cols:
                batch_op.add_column(sa.Column("guest_session_hash", sa.String(), nullable=True))

        scan_indexes = [i["name"] for i in inspector.get_indexes("scan_history")]
        if "ix_scan_history_id" not in scan_indexes:
            op.create_index("ix_scan_history_id", "scan_history", ["id"])
        if "ix_scan_history_user_id" not in scan_indexes:
            op.create_index("ix_scan_history_user_id", "scan_history", ["user_id"])
        if "ix_scan_history_guest_session_hash" not in scan_indexes:
            op.create_index("ix_scan_history_guest_session_hash", "scan_history", ["guest_session_hash"])
        if "ix_scan_history_input_type" not in scan_indexes:
            op.create_index("ix_scan_history_input_type", "scan_history", ["input_type"])

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

        # Enforce invariant: verify no NULL generation_id rows remain
        null_count = conn.execute(sa.text("SELECT COUNT(*) FROM threat_indicators WHERE generation_id IS NULL OR generation_id = ''")).scalar() or 0
        if null_count > 0:
            raise RuntimeError(f"Database migration failed: {null_count} rows in threat_indicators have NULL generation_id.")

        # Reconcile ThreatFeedState for every source in threat_indicators.
        # Timestamps and booleans are bound as parameters (not inline SQL
        # functions) so the statements run identically on SQLite and
        # PostgreSQL.
        now_iso = datetime.now(timezone.utc).isoformat()
        sources = [r[0] for r in conn.execute(sa.text("SELECT DISTINCT source FROM threat_indicators")).fetchall() if r[0]]
        for src in sources:
            legacy_gen = f"legacy-gen-{src}"
            cnt = conn.execute(sa.text("SELECT COUNT(*) FROM threat_indicators WHERE source = :src AND generation_id = :gen"), {"src": src, "gen": legacy_gen}).scalar() or 0
            st = conn.execute(sa.text("SELECT source, current_generation_id FROM threat_feed_states WHERE source = :src"), {"src": src}).fetchone()
            if not st:
                conn.execute(
                    sa.text("""
                        INSERT INTO threat_feed_states (source, enabled, status, freshness, last_success_count, current_generation_id, refresh_interval_seconds, updated_at)
                        VALUES (:src, :enabled, 'idle', 'stale', :cnt, :gen, 86400, :now)
                    """),
                    {"src": src, "enabled": True, "cnt": cnt, "gen": legacy_gen, "now": now_iso}
                )
            else:
                curr_gen = st[1]
                if not curr_gen:
                    conn.execute(
                        sa.text("""
                            UPDATE threat_feed_states
                            SET current_generation_id = :gen, freshness = 'stale', status = 'idle', last_success_at = NULL, last_success_count = :cnt, updated_at = :now
                            WHERE source = :src
                        """),
                        {"src": src, "cnt": cnt, "gen": legacy_gen, "now": now_iso}
                    )
                else:
                    active_cnt = conn.execute(sa.text("SELECT COUNT(*) FROM threat_indicators WHERE source = :src AND generation_id = :curr"), {"src": src, "curr": curr_gen}).scalar() or 0
                    if active_cnt == 0:
                        conn.execute(
                            sa.text("""
                                UPDATE threat_feed_states
                                SET current_generation_id = :gen, freshness = 'stale', status = 'idle', last_success_at = NULL, last_success_count = :cnt, updated_at = :now
                                WHERE source = :src
                            """),
                            {"src": src, "cnt": cnt, "gen": legacy_gen, "now": now_iso}
                        )

        # Batch recreate table to enforce generation_id NOT NULL and replace old UNIQUE(source, indicator_type, indicator_hash)
        # with new UNIQUE(source, generation_id, indicator_type, indicator_hash)
        uq_names = [u.get("name") for u in inspector.get_unique_constraints("threat_indicators") if u.get("name")]
        existing_idx_names = [i["name"] for i in inspector.get_indexes("threat_indicators")]

        # SQLite needs a full table recreate to change constraints;
        # PostgreSQL supports native ALTER statements ("auto").
        recreate_mode = "always" if conn.dialect.name == "sqlite" else "auto"
        with op.batch_alter_table("threat_indicators", recreate=recreate_mode) as batch_op:
            batch_op.alter_column("generation_id", nullable=False, existing_type=sa.String(36))
            if "uq_source_type_indicator" in uq_names:
                batch_op.drop_constraint("uq_source_type_indicator", type_="unique")
            batch_op.create_unique_constraint(
                "uq_source_gen_type_indicator",
                ["source", "generation_id", "indicator_type", "indicator_hash"]
            )
            required_indexes = [
                ("ix_threat_indicators_source", ["source"]),
                ("ix_threat_indicators_indicator_type", ["indicator_type"]),
                ("ix_threat_indicators_indicator_hash", ["indicator_hash"]),
                ("ix_threat_indicators_classification", ["classification"]),
                ("ix_threat_indicators_expires_at", ["expires_at"]),
                ("ix_threat_indicators_generation_id", ["generation_id"]),
            ]
            for idx_name, cols in required_indexes:
                if idx_name not in existing_idx_names:
                    batch_op.create_index(idx_name, cols)
    else:
        # If threat_indicators table is created fresh in this revision
        op.create_table(
            "threat_indicators",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column("source", sa.String(64), nullable=False),
            sa.Column("indicator_type", sa.String(32), nullable=False),
            sa.Column("indicator", sa.String(2048), nullable=False),
            sa.Column("indicator_hash", sa.String(64), nullable=False),
            sa.Column("classification", sa.String(64), nullable=False),
            sa.Column("confidence", sa.Float(), nullable=False, server_default="1.0"),
            sa.Column("observed_at", sa.String(32), nullable=False),
            sa.Column("expires_at", sa.String(32), nullable=True),
            sa.Column("generation_id", sa.String(36), nullable=False),
            sa.Column("created_at", sa.String(32), nullable=False),
            sa.Column("updated_at", sa.String(32), nullable=False),
            sa.UniqueConstraint("source", "generation_id", "indicator_type", "indicator_hash", name="uq_source_gen_type_indicator"),
        )
        op.create_index("ix_threat_indicators_source", "threat_indicators", ["source"])
        op.create_index("ix_threat_indicators_indicator_type", "threat_indicators", ["indicator_type"])
        op.create_index("ix_threat_indicators_indicator_hash", "threat_indicators", ["indicator_hash"])
        op.create_index("ix_threat_indicators_classification", "threat_indicators", ["classification"])
        op.create_index("ix_threat_indicators_expires_at", "threat_indicators", ["expires_at"])
        op.create_index("ix_threat_indicators_generation_id", "threat_indicators", ["generation_id"])


def downgrade() -> None:
    """Downgrade schema: fail closed on cross-generation duplicates to protect data integrity."""
    conn = op.get_bind()
    inspector = sa.inspect(conn)

    if "threat_indicators" in inspector.get_table_names():
        # Check for cross-generation duplicate records
        # HAVING must repeat the aggregate (PostgreSQL does not allow
        # referencing the SELECT alias inside HAVING).
        dups = conn.execute(sa.text("""
            SELECT source, indicator_type, indicator_hash, COUNT(*) as cnt
            FROM threat_indicators
            GROUP BY source, indicator_type, indicator_hash
            HAVING COUNT(*) > 1
        """)).fetchall()

        if dups:
            raise RuntimeError(
                f"Cannot downgrade schema: {len(dups)} cross-generation duplicate indicator groups exist in threat_indicators. "
                "Refusing unsafe destructive rollback."
            )

        uq_names = [u.get("name") for u in inspector.get_unique_constraints("threat_indicators") if u.get("name")]
        existing_idx_names = [i["name"] for i in inspector.get_indexes("threat_indicators")]
        recreate_mode = "always" if conn.dialect.name == "sqlite" else "auto"
        with op.batch_alter_table("threat_indicators", recreate=recreate_mode) as batch_op:
            if "uq_source_gen_type_indicator" in uq_names:
                batch_op.drop_constraint("uq_source_gen_type_indicator", type_="unique")
            if "ix_threat_indicators_generation_id" in existing_idx_names:
                batch_op.drop_index("ix_threat_indicators_generation_id")
            batch_op.drop_column("generation_id")
            batch_op.create_unique_constraint(
                "uq_source_type_indicator",
                ["source", "indicator_type", "indicator_hash"]
            )

    if "threat_feed_states" in inspector.get_table_names():
        op.drop_table("threat_feed_states")
