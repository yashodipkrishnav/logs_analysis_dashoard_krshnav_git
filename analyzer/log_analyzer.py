import paramiko
from datetime import datetime, timedelta
import re


# ---------------- SSH ---------------- #

def connect(host, user, password):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        client.connect(
            hostname=host,
            username=user,
            password=password,
            look_for_keys=False,
            allow_agent=False,
            timeout=10
        )
    except Exception as e:
        return f"ERROR: {str(e)}"   # 🔥 RETURN ERROR

    return client


def execute_command(client, cmd, password):
    sudo_cmd = f"sudo -S -p '' {cmd}"

    stdin, stdout, stderr = client.exec_command(sudo_cmd, timeout=10)

    stdin.write(password + "\n")
    stdin.flush()

    output = stdout.read().decode()
    return output


# ---------------- LOG FILE ---------------- #

def get_log_file(client, search, search_date_str, password):
    search_date = datetime.strptime(search_date_str, "%Y-%m-%d").date()
    today = datetime.utcnow().date()

    live_logs = [
        "/var/log/mail",
        "/var/log/mail.log",
        "/var/log/maillog"
    ]

    gz_logs = [
        "/var/log/mail-{date}.gz",
        "/var/log/mail.log-{date}.gz",
        "/var/log/maillog-{date}.gz"
    ]

    month_day = search_date.strftime("%b %e")

    def has_logs(path, base_cmd):
        cmd = f"{base_cmd} '{search}' {path} | head -1"
        return execute_command(client, cmd, password)

    if search_date == today:
        for log in live_logs:
            if has_logs(log, "grep"):
                return log, False, search_date

    next_day = search_date + timedelta(days=1)
    date_str = next_day.strftime("%Y%m%d")

    for pattern in gz_logs:
        log_file = pattern.format(date=date_str)
        if has_logs(log_file, "zgrep"):
            return log_file, True, search_date

    return None, None, None


# ---------------- SEARCH ---------------- #

def build_command(search, log_file, is_gz, search_date, time_range=None):
    month_day = search_date.strftime("%b %e")
    base_cmd = "zgrep" if is_gz else "grep"

    if time_range:
        start, end = time_range.split("-")

        cmd = (
            f"{base_cmd} '{month_day}.*{search}' {log_file} | "
            f"awk '{{ split($3,t,\":\"); time=t[1]\":\"t[2]; "
            f"if (time >= \"{start}\" && time <= \"{end}\") print }}'"
        )
    else:
        cmd = f"{base_cmd} '{month_day}.*{search}' {log_file}"

    return cmd


# ---------------- QUEUE ---------------- #
def extract_queue_ids_with_limit(log_output, limit=5):
    results = []
    seen = set()

    for line in log_output.splitlines():
        match = re.search(r'\b([A-F0-9]{10,15}):', line)
        if not match:
            continue


        qid = match.group(1)

        if qid in seen:
            continue   # 🔥 skip duplicates immediately

        seen.add(qid)

        # extract time safely
        parts = line.split()
        time = parts[2][:5] if len(parts) > 2 else "??:??"

        results.append((time, qid))

        if len(results) >= limit:
            break

    return results

# ---------------- CLEAN ---------------- #

def clean_log_output(raw_logs):
    cleaned = []

    for line in raw_logs.splitlines():

        if " removed" in line:
            continue

        parts = line.split()

        if len(parts) < 3:
            continue

        timestamp = " ".join(parts[:3])

        message = re.sub(
            r'^\w{3}\s+\d+\s+\d+:\d+:\d+\s+\S+\s+\S+\[\d+\]:\s+[A-F0-9]+:\s*',
            '',
            line
        )

        # fallback if regex didn't match
        if message == line:
            m = re.search(r'[A-F0-9]{8,15}:\s+(.*)', line)
            if m:
                message = m.group(1)

        cleaned.append(f"{timestamp} {message}")

    return "\n".join(cleaned)

# ---------------- FULL LOG ---------------- #

def fetch_full_logs(client, log_file, is_gz, search_date, queue_ids, password):
    month_day = search_date.strftime("%b %e")
    base_cmd = "zgrep" if is_gz else "grep"

    final = ""

    for qid in queue_ids:

        cmd = f"{base_cmd} '{qid}' {log_file} | head -50"
        result = execute_command(client, cmd, password)

        if result:
            final += f"\n===== {qid} =====\n"
            final += clean_log_output(result) + "\n"

    return final

# ---------------- PROCESS HOST ---------------- #

def process_host(host, args, password):
    output = []

    output.append(f"========== {host} ==========")
    output.append("🔌 Connecting...")

    client = connect(host, args.user, password)

    if isinstance(client, str):   # error string
        output.append(client)
        return "\n".join(output)

    if not client:
        output.append("❌ Connection failed")
        return "\n".join(output)

    try:
        output.append("📂 Finding log file...")

        log_file, is_gz, search_date = get_log_file(client, args.search, args.date, password)

        if not log_file:
            output.append("❌ No logs found")
            return "\n".join(output)

        output.append(f"📄 Log file: {log_file}")
        output.append("🔍 Searching logs...")

        cmd = build_command(args.search, log_file, is_gz, search_date, args.time_range)
        logs = execute_command(client, cmd, password)

        if not logs:
            output.append("❌ No matching logs")
            return "\n".join(output)

        output.append("📌 Extracting Queue IDs...")


        queue_list = extract_queue_ids_with_limit(logs, args.limit)

        if not queue_list:
            output.append("⚠️ No Queue IDs found")
        else:
            for t, q in queue_list:
                output.append(
                    f"{t} → <a href='#' onclick='getQueue(\"{host}\", \"{q}\")'>{q}</a>"
#                    f'{t} → <a href="#" onclick="getQueue("{host}", "{q}")">{q}</a>'
                )

    except Exception as e:
        output.append(f"❌ ERROR: {e}")

    finally:
        client.close()

    return "\n".join(output)

# ---------------- MAIN RUNNER ---------------- #

def run_log_analyzer(hosts, user, search, date, time_range=None, limit=5, password=None):
    from concurrent.futures import ThreadPoolExecutor

    args = type('', (), {})()
    args.user = user
    args.search = search
    args.date = date
    args.time_range = time_range
    args.limit = limit

    host_list = [h.strip() for h in hosts.split(",") if h.strip()]

    results = []

    with ThreadPoolExecutor(max_workers=len(host_list)) as executor:
        futures = [
            executor.submit(process_host, host, args, password)
            for host in host_list
        ]

        for f in futures:
            results.append(f.result())

    return "\n\n".join(results)




