from flask import Flask, render_template, request, jsonify, redirect, url_for, session
from analyzer.log_analyzer import run_log_analyzer 
#from analyzer.log_analyzer import run_log_analyzer, fetch_full_logs, get_log_file, build_email_flow
from ldap3 import Server, Connection, ALL
from datetime import timedelta
from analyzer.masquerading import *
#import os

app = Flask(__name__)
app.secret_key = "supersecretkey"
#app.secret_key = os.environ.get("FLASK_SECRET_KEY")

#app.permanent_session_lifetime = timedelta(minutes=30)

# Login Page
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        result = authenticate_ldap(username, password)

        if result is True:
            session["user"] = username
            session["password"] = password
            session.permanent = True
            return redirect(url_for("dashboard"))
        else:
            return render_template(
                "login.html",
                error=result,
                username=username
            )

    return render_template("login.html")


# LDAP auth function

def authenticate_ldap(username, password):
    try:
        LDAP_SERVER = "ldap://10.175.150.10"
        DOMAIN = "onbmc.com"

        user_dn = f"{username}@{DOMAIN}"
        server = Server(LDAP_SERVER)
        conn = Connection(server, user=user_dn, password=password)

        if conn.bind():
            conn.unbind()
            return True
        else:
            code = conn.result.get("message", "")

            if "data 775" in code:
                return "Account locked"
            elif "data 52e" in code:
                return "Invalid account or credentials"
            elif "data 532" in code:
                return "Password expired"
            else:
                return "LDAP authentication failed"

    except Exception as e:
        return f"LDAP ERROR: {str(e)}"

# Logout
@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# 🏠 Dashboard
@app.route("/")
def dashboard():
    if "user" not in session:
        return redirect(url_for("login"))
    return render_template("dashboard.html", user=session["user"])

# Queue ID
@app.route("/queue", methods=["POST"])
def queue_details():
    from analyzer.log_analyzer import fetch_full_logs, get_log_file

    if "user" not in session:
        return jsonify({"result": "Unauthorized"})

    data = request.json

    host = data.get("host")
    qid = data.get("qid")
    search = data.get("search")
    date = data.get("date")

    user = session["user"]
    password = session["password"]

    # Connect
    from analyzer.log_analyzer import connect
    client = connect(host, user, password)

    if isinstance(client, str):
        return jsonify({"result": client})

    log_file, is_gz, search_date = get_log_file(client, search, date, password)

    result = fetch_full_logs(client, log_file, is_gz, search_date, [qid], password)

    client.close()

    return jsonify({"result": result})

# 🚀 Run Analyzer
@app.route("/run", methods=["POST"])
def run():
    if "user" not in session:
        return jsonify({"result": "Unauthorized"})

    data = request.json

    output = run_log_analyzer(
        hosts=data.get("hosts"),
        user=session["user"],              # 🔥 from login
        search=data.get("search"),
        date=data.get("date"),
        time_range=data.get("time_range"),
        limit=int(data.get("limit", 5)),
        password=session["password"]       # 🔥 from login
    )

    return jsonify({"result": output})


# Masquerading

@app.route("/masquerading", methods=["GET", "POST"])
def masquerading():

    if request.method == "GET":
        return render_template(
            "masquerading.html",
            user=session.get("user")
        )

    smtp_host = request.form["smtp_host"]
    domain = request.form["domain"]
    service_ci = request.form["service_ci"]
    option_type = request.form["option_type"]

    vmaps_file = "/etc/postfix/vmaps"
    addressowner_file = "/etc/postfix/addressowner_map"
    relaymap_file = "/etc/postfix/relaymap"
    sasl_file = "/etc/postfix/sasl_passwd"

    spf_valid, spf_result = validate_spf(domain)



    mailboxes = discover_mailboxes(
        smtp_host,
        session["user"],
        session["password"],
        service_ci
    )

    found, addressowner = check_addressowner_map(
        smtp_host,
        session["user"],
        session["password"],
        domain
    )
    
    
    relay_result = ""
    sasl_result = ""


    if option_type == "relay":
    
        _, relay_result = check_relaymap(
            smtp_host,
            session["user"],
            session["password"],
            domain
        )
    
        sasl_result = "Relay host not provided"

#    relay_host = request.form.get("relay_host", "")

#        _, sasl_result = check_sasl_passwd(
#            smtp_host,
#            session["user"],
#            session["password"],
#            relay_host
#        )

    return render_template(
        "masquerading_result.html",
        smtp_host=smtp_host,
        domain=domain,
        option_type=option_type,
        spf_valid=spf_valid,
        spf_result=spf_result,
        mailboxes=mailboxes,
        addressowner_result=addressowner,
        relay_result=relay_result,
        sasl_result=sasl_result
    )

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
