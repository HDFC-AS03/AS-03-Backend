from fastapi import HTTPException
from app.auth.dependencies import require_role


def test_require_role_denied():

    checker = require_role("admin")

    try:
        checker({"roles": ["user"]})
    except HTTPException as e:
        assert e.status_code == 403