from crypto_utils import verify_password_strength, password_score

def test_strong_password():
    ok, _ = verify_password_strength("StrongPassword!123")
    assert ok

def test_weak_password():
    ok, _ = verify_password_strength("password")
    assert not ok

def test_password_score():
    assert password_score("abc") < password_score("Abcdef123!xyz")
