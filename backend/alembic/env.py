import os
import sys
from logging.config import fileConfig

from sqlalchemy import engine_from_config
from sqlalchemy import pool

from alembic import context

# Add backend directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.config import normalize_database_url
from app.db import Base, SQLALCHEMY_DATABASE_URL
import app.models.domain  # noqa

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def _resolve_alembic_url() -> str:
    """
    Single-source-of-truth URL resolution, in priority order:

    1. A programmatic override (e.g. tests calling
       Config.set_main_option("sqlalchemy.url", ...)) — detected because it
       differs from the static value in alembic.ini.
    2. The DATABASE_URL environment variable (normalized exactly like the
       application does), so deployments migrate the same database the
       application connects to.
    3. The application's resolved database URL from app.db, which already
       applies the environment contract (SQLite fallback in development/test,
       mandatory PostgreSQL in staging/production).
    """
    # Read the pristine value straight from the ini file on disk:
    # Config.set_main_option() mutates the in-memory file_config, so only a
    # fresh parse can distinguish a programmatic override from the ini value.
    ini_url = None
    if config.config_file_name is not None:
        import configparser

        parser = configparser.ConfigParser()
        parser.read(config.config_file_name)
        if parser.has_option("alembic", "sqlalchemy.url"):
            ini_url = parser.get("alembic", "sqlalchemy.url", raw=True)

    current = config.get_main_option("sqlalchemy.url")
    if current and current != ini_url:
        return current

    env_url = normalize_database_url(os.getenv("DATABASE_URL", ""))
    if env_url:
        return env_url

    return SQLALCHEMY_DATABASE_URL


# configparser interpolation requires escaping literal '%' characters.
config.set_main_option("sqlalchemy.url", _resolve_alembic_url().replace("%", "%%"))

# other values from the config, defined by the needs of env.py,
# can be acquired:
# my_important_option = config.get_main_option("my_important_option")
# ... etc.


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode.

    This configures the context with just a URL
    and not an Engine, though an Engine is acceptable
    here as well.  By skipping the Engine creation
    we don't even need a DBAPI to be available.

    Calls to context.execute() here emit the given string to the
    script output.

    """
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode.

    In this scenario we need to create an Engine
    and associate a connection with the context.

    """
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection, target_metadata=target_metadata
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
