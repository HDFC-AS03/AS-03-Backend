from app.jwt_utils import _jwks_cache


def test_jwks_cache_clear():
    # ensure cache can be set and cleared
    _jwks_cache['jwks'] = {'keys': []}
    assert 'jwks' in _jwks_cache
    _jwks_cache.clear()
    assert 'jwks' not in _jwks_cache
