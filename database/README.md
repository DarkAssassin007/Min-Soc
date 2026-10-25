# database/

This directory is part of the required repository layout (master spec §30).
The schema, models and repository live with the backend:

| concern | location |
|---------|----------|
| SQLAlchemy models | `backend/app/database/models.py` |
| engine + WAL tuning | `backend/app/database/connection.py` |
| repository / queries | `backend/app/database/repository.py` |
| schema bootstrap | `backend/app/database/connection.py::init_db` (created automatically on startup) |
| first administrator | `POST /api/v1/auth/bootstrap` (allowed only while no user exists) |
| runtime database | `data/mini_soc.db` (SQLite, WAL) or any PostgreSQL via `MINI_SOC_DATABASE_URL` |
| schema reference | [docs/database](../docs/database/README.md) |

The pipeline is the only writer to event/detection/alert tables; reads are
served concurrently through WAL. See the architecture notes for the
single-writer design and the optional PostgreSQL deployment profile.
