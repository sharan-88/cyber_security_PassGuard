# PassGuard – Password Strength & Security Analyzer

Analyzes a password locally and explains how it could be attacked: score (0–100),
verdict, entropy, crack-time estimate, findings and suggestions. Includes a secure
password generator (Python `secrets`). Nothing is stored, logged or sent anywhere.

![landing page](https://github.com/sharan-88/cyber_security_PassGuard/blob/main/Screenshot%202026-10-06%20214045.png)

![example](https://github.com/sharan-88/cyber_security_PassGuard/blob/main/Screenshot%202026-10-06%20214110.png)


## Run
```bash
pip install -r requirements.txt
python app.py            # open http://127.0.0.1:5000
python -m pytest -q      # run the tests
```

## Structure
```
app.py            Flask app + REST API
analyzer.py       Rules, entropy, pattern detection, scoring, crack time, generator
data.py           Common-password and dictionary-word lists, keyboard rows, leet map
templates/        index.html
static/           style.css, app.js
tests/            test_passguard.py
```

## API
| Method | Endpoint | Body / query | Returns |
|---|---|---|---|
| POST | `/api/analyze` | `{"password": "..."}` | score, level, entropy_bits, crack_time, checks, findings, suggestions |
| GET/POST | `/api/generate` | `length` (8–64), `symbols` | generated password plus its analysis |

```bash
curl -s -X POST localhost:5000/api/analyze -H "Content-Type: application/json" \
     -d '{"password":"Welcome@2024"}'
```

## How the score works
1. Rule checks: length ≥ 12, lowercase, uppercase, digit, symbol.
2. Pattern detection: common passwords, leetspeak, dictionary words, sequences, repeats, keyboard walks, years.
3. Entropy = length × log2(pool size); each detected pattern is priced at a small fixed cost instead.
4. Score = entropy (capped at 100), with caps for common / word-based / very short passwords.
5. Levels: 0–19 Very Weak, 20–39 Weak, 40–59 Fair, 60–79 Strong, 80–100 Very Strong.
6. Crack time = 2^entropy / 2 at 10 billion guesses per second.

## Privacy
Passwords are processed in memory only, never echoed in responses, and every response
carries `Cache-Control: no-store`. Debug mode is off, a strict CSP is set and no external
services or fonts are loaded.
