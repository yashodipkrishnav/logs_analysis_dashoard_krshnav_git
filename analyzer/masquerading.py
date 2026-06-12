import re
import dns.resolver
import os
import paramiko


def run_remote_command(hostname, username, password, command):

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    ssh.connect(
        hostname,
        username=username,
        password=password,
        timeout=10
    )

    stdin, stdout, stderr = ssh.exec_command(command)
    output = stdout.read().decode()
    error = stderr.read().decode()

    ssh.close()
    return output, error

def validate_spf(domain):
    try:
        records = dns.resolver.resolve(domain, 'TXT')

        for record in records:
            txt = ''.join([part.decode() if isinstance(part, bytes) else part
                           for part in record.strings])

            if txt.startswith("v=spf1"):
                return True, txt
        return False, "SPF record not found"
    except Exception as e:
        return False, str(e)



def discover_mailboxes(smtp_host, username, password, service_ci):
    mailboxes = []

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    ssh.connect(
        smtp_host,
        username=username,
        password=password
    )

    cmd = "grep '@{}' /etc/postfix/vmaps".format(service_ci)
    stdin, stdout, stderr = ssh.exec_command(cmd)
    output = stdout.read().decode()
    ssh.close()

    for line in output.splitlines():
        if line.strip():
            email = line.split()[0]
            if email not in mailboxes:
                mailboxes.append(email)

    return sorted(mailboxes)

def check_addressowner_map(smtp_host, username, password, domain):

    cmd = "grep '^@{}' /etc/postfix/addressowner_map".format(domain)

    output, error = run_remote_command(
        smtp_host,
        username,
        password,
        cmd
    )

    if output.strip():
        return True, output.strip()

    return False, "Domain not found"

def check_relaymap(smtp_host, username, password, domain):

    cmd = "grep '^@{}' /etc/postfix/relaymap".format(domain)

    output, error = run_remote_command(
        smtp_host,
        username,
        password,
        cmd
    )

    if output.strip():
        return True, output.strip()

    return False, "Domain not found"

def check_sasl_passwd(smtp_host, username, password, relay_host):

    cmd = "grep '{}' /etc/postfix/sasl_passwd".format(relay_host)

    output, error = run_remote_command(
        smtp_host,
        username,
        password,
        cmd
    )

    if output.strip():
        return True, output.strip()

    return False, "Not found"
