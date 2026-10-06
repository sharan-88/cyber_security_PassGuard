import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analyzer import analyze, crack_time, format_duration, generate_password  # noqa: E402
from app import app  # noqa: E402


@pytest.fixture
def client():
    app.config["TESTING"] = True
    return app.test_client()


# ---------------- analyzer ----------------
def test_common_password():
    r = analyze("password")
    assert r["score"] <= 5 and r["level"] == "Very Weak"


def test_leetspeak_password_detected_as_common():
    r = analyze("P@ssw0rd")
    assert r["score"] <= 15
    assert any("common" in f.lower() for f in r["findings"])


def test_word_plus_year_is_weak():
    assert analyze("Welcome@2024")["level"] in ("Weak", "Very Weak")


def test_word_with_digits_is_weak():
    assert analyze("password123")["level"] in ("Weak", "Very Weak")


def test_strong_random_password():
    r = analyze("Xk9#mP2$vL7qRz!w")
    assert r["score"] >= 80 and r["level"] == "Very Strong"


def test_medium_password_is_strong():
    assert analyze("Tr0ub4dor&3")["level"] == "Strong"


def test_sequence_detected():
    assert any("sequence" in f.lower() for f in analyze("xyzabc123Qm")["findings"])


def test_repeated_characters_detected():
    assert any("repeated" in f.lower() for f in analyze("aaaaaaaa")["findings"])


def test_keyboard_pattern_detected():
    assert any("keyboard" in f.lower() for f in analyze("zxcvbnmQ9")["findings"])


def test_checklist():
    c = analyze("Abcdef1!")["checks"]
    assert c == {"length": False, "lowercase": True, "uppercase": True, "digit": True, "symbol": True}


def test_empty_password():
    r = analyze("")
    assert r["score"] == 0 and r["entropy_bits"] == 0


def test_crack_time_grows_with_entropy():
    assert crack_time(80)[0] > crack_time(40)[0]
    assert format_duration(0.1) == "Instantly"


# ---------------- generator ----------------
def test_generator_length_and_classes():
    for n in (8, 16, 64):
        p = generate_password(n)
        assert len(p) == n
        assert any(c.islower() for c in p) and any(c.isupper() for c in p)
        assert any(c.isdigit() for c in p) and any(not c.isalnum() for c in p)


def test_generator_rejects_bad_length():
    with pytest.raises(ValueError):
        generate_password(7)
    with pytest.raises(ValueError):
        generate_password(65)


def test_generated_passwords_differ():
    assert len({generate_password(20) for _ in range(50)}) == 50


# ---------------- API / privacy ----------------
def test_api_does_not_echo_password_and_is_not_cached(client):
    secret = "S3cr3t!Value#99"
    r = client.post("/api/analyze", json={"password": secret})
    assert r.status_code == 200
    assert secret not in r.get_data(as_text=True)
    assert "no-store" in r.headers["Cache-Control"]
    for key in ("score", "level", "entropy_bits", "crack_time", "checks", "findings", "suggestions"):
        assert key in r.get_json()


def test_api_rejects_bad_input(client):
    assert client.post("/api/analyze", json={}).status_code == 400
    assert client.post("/api/analyze", json={"password": 123}).status_code == 400
    assert client.post("/api/analyze", json={"password": "a" * 500}).status_code == 400


def test_api_generate(client):
    r = client.get("/api/generate?length=20")
    d = r.get_json()
    assert r.status_code == 200 and len(d["password"]) == 20
    assert client.get("/api/generate?length=3").status_code == 400
    assert client.get("/api/generate?length=abc").status_code == 400


def test_home_page(client):
    r = client.get("/")
    assert r.status_code == 200 and b"PassGuard" in r.data
