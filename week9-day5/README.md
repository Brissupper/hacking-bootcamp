# Hacking Bootcamp - Week 9: Mobile & Cloud Hacking

## Day 5: Container Escapes. Docker Breakout.

### Overview
Explored Docker container isolation weaknesses. Performed breakouts via privileged mode, volume mounts, and socket access. Diversified into malware: keyloggers and RATs for host and mobile.

### Techniques
- **Breakout Methods**: Privileged containers for root access, mounted sockets for daemon control.
- **Malware**: C/Python keyloggers with persistence, RAT for command exfil, Frida hooks for Android interception.
- **Evasion**: Root bypasses, obfuscation, polymorphic code.

### Files
- `rootkit.c`: C keylogger.
- `advanced_keylogger.py`: Python keylogger with exfil.
- `android_rat.py`: RAT for host/mobile.
- `sms_hook.js`: Frida hook for SMS.

### Usage
Run in Kali VM. Breakout: `docker run --privileged ubuntu bash` -> mount /dev/sda1 -> chroot.
Malware: `python3 advanced_keylogger.py &`
