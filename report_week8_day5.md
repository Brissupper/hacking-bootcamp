# Week 8 Day 5: Web Shell Deployment Chain Report

## Objective
Deploy custom Python web shell, persist, diversify with patches.

## Environment
Kali VM: Apache/PHP/MariaDB fixed.

## Scans
- Nmap: Open 80, 3306.
- MariaDB: Root access via unix_socket.

## Exploits
- Upload: shell.py to /home/kali, run on 8080.
- RCE: POST to /shell with base64 cmds (e.g., whoami).
- Persistence: Systemd auto-start post-reboot.

## Patches
- Whitelist exts, rename uploads.

## Instincts Honed
- Evasion: Base64, persistence.
- Grey Mindset: Ethical deploy with fixes.

## Next: Day 6 Reports
Chain scans into API vuln docs.
