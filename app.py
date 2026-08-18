from flask import Flask, render_template, request, jsonify
import hashlib
import requests

app = Flask(__name__)


# =========================
# HOME PAGE
# =========================
@app.route("/")
def home():
    return render_template("index.html")


# =========================
# PASSWORD BREACH CHECKER
# =========================
@app.route("/check-breach", methods=["POST"])
def check_breach():

    data = request.get_json()

    if not data:
        return jsonify({
            "error": "No password received."
        }), 400

    password = data.get("password", "")

    if not password:
        return jsonify({
            "error": "Please enter a password."
        }), 400

    try:
        # Create SHA-1 hash locally
        sha1_hash = hashlib.sha1(
            password.encode("utf-8")
        ).hexdigest().upper()

        # Only the first 5 characters are sent to HIBP
        prefix = sha1_hash[:5]
        suffix = sha1_hash[5:]

        url = f"https://api.pwnedpasswords.com/range/{prefix}"

        response = requests.get(
            url,
            headers={
                "Add-Padding": "true",
                "User-Agent": "CyberSafe-Password-Breach-Checker"
            },
            timeout=10
        )

        if response.status_code != 200:
            return jsonify({
                "error": "Unable to check the password right now."
            }), 500

        # Search the returned hash suffixes locally
        for line in response.text.splitlines():

            hash_suffix, count = line.split(":")

            if hash_suffix == suffix:

                return jsonify({
                    "breached": True,
                    "count": int(count)
                })

        # Password was not found
        return jsonify({
            "breached": False,
            "count": 0
        })

    except requests.RequestException:

        return jsonify({
            "error": "Could not connect to the breach-checking service."
        }), 500

    except Exception:

        return jsonify({
            "error": "Something went wrong while checking the password."
        }), 500


# =========================
# RUN FLASK
# =========================
if __name__ == "__main__":
    app.run(
        debug=True,
        host="127.0.0.1",
        port=5000
    )