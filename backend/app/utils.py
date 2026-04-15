"""Shared utility helpers — single source of truth for common patterns."""


def rows_as_dicts(cursor):
    """Convert cursor results to a list of dicts keyed by column name.

    Eliminates fragile positional-index access (row[0], row[47], etc.)
    by using cursor.description to map column names.

    Usage:
        cursor.execute("SELECT id, name FROM users")
        rows = rows_as_dicts(cursor)
        for row in rows:
            print(row['id'], row['name'])
    """
    cols = [d[0] for d in cursor.description]
    return [dict(zip(cols, row)) for row in cursor.fetchall()]
