import os
import yara
from flask import Flask, request, render_template, redirect, url_for

app = Flask(__name__)
app.config["UPLOAD_FOLDER"] = "uploads/"
app.config["ALLOWED_EXTENSIONS"] = {"exe", "txt", "bin", "dll"}

os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

RULES_PATH = "malware_rules.yar"
rules = yara.compile(filepath=RULES_PATH)

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in app.config["ALLOWED_EXTENSIONS"]

def scan_file(filepath):
    """ Scan a file with YARA rules and return detection results. """
    matches = rules.match(filepath)
    return matches if matches else None

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        if "file" not in request.files:
            return redirect(request.url)

        file = request.files["file"]

        if file.filename == "":
            return redirect(request.url)

        if file and allowed_file(file.filename):
            filepath = os.path.join(app.config["UPLOAD_FOLDER"], file.filename)
            file.save(filepath)

            matches = scan_file(filepath)
            return render_template("index.html", filename=file.filename, matches=matches)

    return render_template("index.html", filename=None, matches=None)

if __name__ == "__main__":
    app.run(debug=True)
