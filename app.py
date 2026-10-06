"""PassGuard - Flask REST API and web page."""
from flask import Flask, jsonify, render_template, request

from analyzer import MAX_LENGTH, analyze, generate_password

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 4 * 1024  # tiny bodies only


@app.after_request
def privacy_headers(resp):
    """Make sure nothing is cached by the browser or a proxy."""
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    resp.headers["Pragma"] = "no-cache"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; style-src 'self'; script-src 'self'; "
        "connect-src 'self'; img-src 'self' data:"
    )
    return resp


@app.get("/")
def index():
    return render_template("index.html")


@app.post("/api/analyze")
def api_analyze():
    data = request.get_json(silent=True)
    if not isinstance(data, dict) or not isinstance(data.get("password"), str):
        return jsonify(error="Send JSON like {\"password\": \"...\"}."), 400
    password = data["password"]
    if len(password) > MAX_LENGTH:
        return jsonify(error=f"Password must be at most {MAX_LENGTH} characters."), 400
    return jsonify(analyze(password))  # the password is never echoed back


@app.route("/api/generate", methods=["GET", "POST"])
def api_generate():
    payload = request.get_json(silent=True) or {}
    raw_len = payload.get("length", request.args.get("length", 16))
    raw_sym = payload.get("symbols", request.args.get("symbols", True))
    try:
        length = int(raw_len)
        symbols = raw_sym not in (False, "false", "0", 0, "no")
        password = generate_password(length, symbols)
    except (TypeError, ValueError):
        return jsonify(error="length must be a number between 8 and 64."), 400
    result = analyze(password)
    result["password"] = password
    return jsonify(result)


@app.errorhandler(413)
def too_large(_):
    return jsonify(error="Request too large."), 413


if __name__ == "__main__":
    # debug is off on purpose: the debugger would expose request data on errors
    app.run(host="127.0.0.1", port=5000, debug=False)
