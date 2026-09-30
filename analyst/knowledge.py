"""Curated service knowledge base for the local analyst (V0.2).

Each entry describes one network service in plain language: what it is,
why an exposed instance matters, and concrete remediation steps ordered by
priority. All content is static and ships with the platform — the analyst
never calls an external service, keeping the local-first privacy promise.

Keys are the service labels used by agent/discovery.py PORTS.
"""

from __future__ import annotations

from typing import Dict, List, TypedDict


class ServiceKnowledge(TypedDict):
    what: str               # plain-English description of the service
    risk: str               # why exposure matters (real-world context)
    remediation_steps: List[str]  # concrete actions, highest priority first


SERVICE_KB: Dict[str, ServiceKnowledge] = {
    "FTP": {
        "what": "FTP (File Transfer Protocol) moves files between computers. "
                "It is one of the oldest network protocols still in use.",
        "risk": "FTP sends usernames, passwords, and file contents in cleartext, "
                "so anyone on the same network path can capture credentials with "
                "a packet sniffer. Misconfigured servers also allow anonymous "
                "uploads, which attackers use to host malware.",
        "remediation_steps": [
            "Disable FTP if you do not actively use it.",
            "If file transfer is needed, switch to SFTP or SCP (file transfer over SSH), which encrypt everything.",
            "If FTP must stay, restrict it to trusted hosts at the firewall and disable anonymous access.",
        ],
    },
    "SSH": {
        "what": "SSH (Secure Shell) gives encrypted remote command-line access. "
                "It is the standard way to administer servers and devices like this one.",
        "risk": "SSH itself is secure, but it is the most brute-forced service on "
                "the internet: bots try thousands of username/password combinations "
                "per day. Password-only logins and outdated server software are the "
                "usual way in.",
        "remediation_steps": [
            "Use SSH key authentication and disable password authentication if possible.",
            "Disable direct root login (PermitRootLogin no).",
            "Keep the SSH server patched; consider fail2ban or rate limiting to slow brute force.",
            "Do not expose SSH to the internet unless you need remote access from outside.",
        ],
    },
    "Telnet": {
        "what": "Telnet provides remote command-line access, like SSH but designed "
                "in the 1960s — it encrypts nothing.",
        "risk": "Every keystroke, including the login password, travels in cleartext. "
                "Telnet is obsolete; its presence usually means a forgotten or "
                "default-configured device, and attackers actively scan for it.",
        "remediation_steps": [
            "Disable Telnet entirely — there is no safe way to run it.",
            "Use SSH for remote administration instead.",
            "If a device only offers Telnet, isolate that device on a management network or replace it.",
        ],
    },
    "SMTP": {
        "what": "SMTP (Simple Mail Transfer Protocol) is how email gets sent "
                "between mail servers and from mail clients.",
        "risk": "An SMTP server that relays mail for anyone (open relay) gets "
                "abused by spammers within hours of being discovered, which gets "
                "your IP blocklisted. Even a proper server can leak valid usernames "
                "through probing.",
        "remediation_steps": [
            "Confirm this mail service is intentional and needed.",
            "Require authentication for sending, and disable open relay.",
            "If it only needs to send local alerts, bind it to localhost.",
        ],
    },
    "DNS": {
        "what": "DNS (Domain Name System) translates names like example.com into "
                "IP addresses. Many home routers run a DNS forwarder for the LAN.",
        "risk": "A DNS resolver that answers queries from untrusted networks can be "
                "abused for reflection/amplification DDoS attacks, making your "
                "network an unwilling participant and saturating your connection.",
        "remediation_steps": [
            "If this is a resolver, make sure recursion is only offered to your own network, not the internet.",
            "Keep the DNS software patched.",
        ],
    },
    "HTTP": {
        "what": "HTTP serves web pages and web dashboards without encryption. "
                "Routers, printers, cameras, and apps commonly expose one on the LAN.",
        "risk": "Traffic — including any login forms — travels in cleartext and can "
                "be read or modified on the network path. Exposed HTTP often hides "
                "admin panels, setup wizards, or directory listings that leak "
                "configuration details.",
        "remediation_steps": [
            "Prefer HTTPS wherever the device supports it.",
            "Check for exposed admin panels or setup wizards and protect them with a strong password.",
            "Look for directory listings or debug pages and disable them.",
        ],
    },
    "POP3": {
        "what": "POP3 downloads email from a mail server to a single device.",
        "risk": "Plain POP3 sends the mailbox username and password in cleartext, "
                "so they can be captured on the network. It is also easy to "
                "misconfigure into leaving mail accessible without authentication.",
        "remediation_steps": [
            "Switch clients to POP3S (POP3 over TLS) or IMAPS.",
            "Ensure the server requires authentication before revealing any mailbox.",
        ],
    },
    "IMAP": {
        "what": "IMAP lets mail apps read and organize email kept on the server, "
                "synced across multiple devices.",
        "risk": "Plain IMAP transmits login credentials in cleartext. Because it "
                "stays logged in, a captured session can expose the entire mailbox.",
        "remediation_steps": [
            "Switch clients to IMAPS (IMAP over TLS).",
            "Ensure authentication is required and consider app-specific passwords.",
        ],
    },
    "HTTPS": {
        "what": "HTTPS is HTTP wrapped in TLS encryption — the padlock in a "
                "browser. It protects web traffic from eavesdropping and tampering.",
        "risk": "Exposure itself is usually fine, but misconfigured HTTPS still "
                "causes incidents: expired or self-signed certificates train users "
                "to click through warnings, and old TLS versions have known attacks.",
        "remediation_steps": [
            "Check the certificate is valid, unexpired, and issued for the right name.",
            "Disable TLS 1.0/1.1 and weak ciphers; prefer TLS 1.2+.",
            "Confirm whatever the site hosts (admin panel, app) requires authentication.",
        ],
    },
    "SMB": {
        "what": "SMB (Server Message Block) shares files and printers across a "
                "network. Windows machines and many NAS devices speak it.",
        "risk": "SMB is a classic lateral-movement channel: ransomware like "
                "WannaCry spread network-to-network through SMB flaws, and exposed "
                "shares leak files or accept malicious ones. It should never face "
                "untrusted networks.",
        "remediation_steps": [
            "Block SMB at the firewall so it is reachable only from trusted hosts.",
            "Require SMB signing and disable the ancient SMBv1 dialect.",
            "Use strong, unique credentials on every share; audit which shares exist.",
        ],
    },
    "MSSQL": {
        "what": "Microsoft SQL Server listens here for database connections from "
                "applications.",
        "risk": "Database listeners facing untrusted networks are a direct path to "
                "your data: weak sa passwords and unpatched servers are routinely "
                "ransomed or exfiltrated by automated scanners.",
        "remediation_steps": [
            "Restrict access by firewall or IP allowlist to only the app servers that need it.",
            "Use strong unique passwords (especially the sa account) and keep the engine patched.",
            "If only local apps use it, bind the listener to localhost.",
        ],
    },
    "MySQL": {
        "what": "MySQL/MariaDB listens here for database connections from "
                "applications.",
        "risk": "Exposed database ports are swept constantly by bots hunting for "
                "default or weak credentials; a compromised database means stolen "
                "or ransomed data.",
        "remediation_steps": [
            "Restrict access by firewall or IP allowlist to only the hosts that need it.",
            "Use strong unique passwords for every account; remove anonymous/test accounts.",
            "If only local apps use it, bind the listener to 127.0.0.1.",
        ],
    },
    "PostgreSQL": {
        "what": "PostgreSQL listens here for database connections from applications.",
        "risk": "Like any database listener, exposure to untrusted networks invites "
                "credential-guessing bots; a breach puts the full dataset at risk.",
        "remediation_steps": [
            "Restrict access by firewall or IP allowlist (pg_hba.conf) to only the hosts that need it.",
            "Require SCRAM or certificate authentication; avoid 'trust' entries for remote hosts.",
            "If only local apps use it, bind the listener to localhost.",
        ],
    },
    "MongoDB": {
        "what": "MongoDB is a document database popular with web applications.",
        "risk": "MongoDB historically shipped with no authentication enabled, and "
                "tens of thousands of exposed instances have been wiped and held "
                "for ransom. It remains one of the most-scanned database ports.",
        "remediation_steps": [
            "Enable authentication and create dedicated users with least privilege.",
            "Bind to localhost unless remote apps genuinely need access, then firewall it.",
            "Keep the server patched.",
        ],
    },
    "Redis": {
        "what": "Redis is an in-memory data store used as a cache, queue, or "
                "session store by applications.",
        "risk": "Redis has no authentication by default and can be tricked into "
                "writing attacker files to disk, which has led to full server "
                "compromise in real incidents.",
        "remediation_steps": [
            "Bind Redis to localhost and set a strong requirepass password.",
            "Firewall the port so only application hosts can reach it.",
            "Disable dangerous commands (FLUSHALL, CONFIG, EVAL) if exposed beyond localhost.",
        ],
    },
    "RDP": {
        "what": "RDP (Remote Desktop Protocol) gives full graphical remote control "
                "of a Windows machine.",
        "risk": "RDP exposed to untrusted networks is one of the top ransomware "
                "entry points (per CISA): attackers brute-force or buy credentials, "
                "log in, and deploy ransomware with a GUI.",
        "remediation_steps": [
            "Do not expose RDP to the internet — require a VPN connection first.",
            "Enforce multi-factor authentication and account lockout policies.",
            "Keep Windows patched and restrict RDP to specific users, not the whole machine.",
        ],
    },
    "VNC": {
        "what": "VNC shares a computer's screen and keyboard/mouse over the network "
                "for remote control.",
        "risk": "Classic VNC authentication is weak and easily brute-forced, and "
                "sessions may be unencrypted — an attacker who connects sees and "
                "controls everything on screen.",
        "remediation_steps": [
            "Tunnel VNC over SSH or a VPN instead of exposing the port directly.",
            "Set a long, unique VNC password (8+ characters minimum, longer is better).",
            "Disable VNC when you are not actively using it.",
        ],
    },
    "HTTP-alt": {
        "what": "This is a web service on the alternate HTTP port 8080 — often a "
                "device admin page, development server, or app dashboard.",
        "risk": "Alternate-port web services are frequently forgotten: default "
                "credentials, debug mode, or no authentication at all. Attackers "
                "scan 8080 specifically for this reason.",
        "remediation_steps": [
            "Identify what is serving here and confirm it should be running.",
            "Protect it with authentication and a strong unique password.",
            "Do not expose dev servers or dashboards to untrusted networks.",
        ],
    },
    "HTTPS-alt": {
        "what": "This is an encrypted web service on the alternate port 8443 — "
                "often a device admin page or app dashboard.",
        "risk": "Like its HTTP-alt cousin, these are often admin interfaces with "
                "default credentials, plus the extra risk that an invalid or "
                "self-signed certificate teaches users to ignore warnings.",
        "remediation_steps": [
            "Identify what is serving here and confirm it should be running.",
            "Verify the TLS certificate and protect the interface with strong authentication.",
            "Do not expose admin dashboards to untrusted networks.",
        ],
    },
}

UNKNOWN_SERVICE: ServiceKnowledge = {
    "what": "An unrecognized service is listening on this port. The platform knows "
            "common ports, but anything can listen on any port.",
    "risk": "Unknown services are a blind spot: it could be legitimate software, a "
            "forgotten install, or something malicious. You cannot assess risk you "
            "cannot identify.",
    "remediation_steps": [
        "Identify the process: on the host, check which program holds this port (e.g. ss -tlnp).",
        "If it is not needed, stop and disable the service.",
        "If it is needed, document what it is and restrict it to trusted networks at the firewall.",
    ],
}

HOST_UNRESPONSIVE: ServiceKnowledge = {
    "what": "The host did not answer any TCP probes — every connection attempt "
            "timed out.",
    "risk": "This is usually benign (the host is off or asleep), but it can also "
            "mean a firewall is silently dropping probes, which would hide real "
            "services from this scan.",
    "remediation_steps": [
        "Verify whether the host should be online right now.",
        "If it should be up, check its host firewall and that it is on the expected network.",
        "Re-run discovery when the host is awake for a complete picture.",
    ],
}
