"""initial_schema

Revision ID: a1b2c3d4e5f6
Revises: 
Create Date: 2026-10-04 12:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'a1b2c3d4e5f6'
down_revision: Union[str, Sequence[str], None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Create initial tables: users, user_sessions, scan_history, and legacy threat_indicators."""
    conn = op.get_bind()
    inspector = sa.inspect(conn)
    existing_tables = inspector.get_table_names()

    # 1. users table
    if "users" not in existing_tables:
        op.create_table(
            "users",
            sa.Column("id", sa.String(), primary_key=True),
            sa.Column("email", sa.String(), nullable=False),
            sa.Column("hashed_password", sa.String(), nullable=False),
            sa.Column("role", sa.String(), nullable=False, server_default="user"),
            sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("1")),
            sa.Column("created_at", sa.String(), nullable=True),
        )
        op.create_index("ix_users_id", "users", ["id"])
        op.create_index("ix_users_email", "users", ["email"], unique=True)

    # 2. user_sessions table
    if "user_sessions" not in existing_tables:
        op.create_table(
            "user_sessions",
            sa.Column("id", sa.String(), primary_key=True),
            sa.Column("user_id", sa.String(), sa.ForeignKey("users.id"), nullable=False),
            sa.Column("session_id_hash", sa.String(), nullable=False),
            sa.Column("created_at", sa.String(), nullable=True),
            sa.Column("expires_at", sa.String(), nullable=False),
            sa.Column("revoked_at", sa.String(), nullable=True),
        )
        op.create_index("ix_user_sessions_id", "user_sessions", ["id"])
        op.create_index("ix_user_sessions_user_id", "user_sessions", ["user_id"])
        op.create_index("ix_user_sessions_session_id_hash", "user_sessions", ["session_id_hash"], unique=True)

    # 3. scan_history table
    if "scan_history" not in existing_tables:
        op.create_table(
            "scan_history",
            sa.Column("id", sa.String(), primary_key=True),
            sa.Column("user_id", sa.String(), sa.ForeignKey("users.id"), nullable=True),
            sa.Column("guest_session_hash", sa.String(), nullable=True),
            sa.Column("timestamp", sa.String(), nullable=True),
            sa.Column("input_type", sa.String(), nullable=True),
            sa.Column("content", sa.String(), nullable=True),
            sa.Column("risk_score", sa.Integer(), nullable=True),
            sa.Column("status", sa.String(), nullable=True),
            sa.Column("phishing_signals", sa.JSON(), nullable=True),
            sa.Column("ai_explanation", sa.String(), nullable=True),
            sa.Column("details", sa.JSON(), nullable=True),
        )
        op.create_index("ix_scan_history_id", "scan_history", ["id"])
        op.create_index("ix_scan_history_user_id", "scan_history", ["user_id"])
        op.create_index("ix_scan_history_guest_session_hash", "scan_history", ["guest_session_hash"])
        op.create_index("ix_scan_history_input_type", "scan_history", ["input_type"])

    # 4. threat_indicators table (legacy pre-Task-3 structure)
    if "threat_indicators" not in existing_tables:
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
            sa.Column("created_at", sa.String(32), nullable=False),
            sa.Column("updated_at", sa.String(32), nullable=False),
            sa.UniqueConstraint("source", "indicator_type", "indicator_hash", name="uq_source_type_indicator"),
        )
        op.create_index("ix_threat_indicators_source", "threat_indicators", ["source"])
        op.create_index("ix_threat_indicators_indicator_type", "threat_indicators", ["indicator_type"])
        op.create_index("ix_threat_indicators_indicator_hash", "threat_indicators", ["indicator_hash"])
        op.create_index("ix_threat_indicators_classification", "threat_indicators", ["classification"])
        op.create_index("ix_threat_indicators_expires_at", "threat_indicators", ["expires_at"])


def downgrade() -> None:
    """Drop initial tables."""
    conn = op.get_bind()
    inspector = sa.inspect(conn)
    existing_tables = inspector.get_table_names()

    if "threat_indicators" in existing_tables:
        op.drop_table("threat_indicators")
    if "scan_history" in existing_tables:
        op.drop_table("scan_history")
    if "user_sessions" in existing_tables:
        op.drop_table("user_sessions")
    if "users" in existing_tables:
        op.drop_table("users")
