# net-run

Multi-protocol credential validator and quick-enum tool built on [NetExec (nxc)](https://github.com/Penntest-dev/NetExec). Spray creds across 9 protocols in parallel, auto-enumerate on wins.

```
                __
  ____   ____ _/  |_         _______ __ __  ____
 /    \_/ __ \\   __\ ______ \_  __ \  |  \/    \
|   |  \  ___/ |  |  /_____/  |  | \/  |  /   |  \
|___|  /\___  >|__|           |__|  |____/|___|  /
     \/     \/                                 \/
```

## What It Does

1. **Validates credentials** against SMB, LDAP, MSSQL, RDP, WinRM, FTP, SSH, VNC, and WMI — all in parallel
2. **Detects admin access** (`Pwn3d!`) and flags it separately from basic auth
3. **Auto-enumerates** on successful protocols (shares, users, groups, AS-REP/Kerberoast, MSSQL privs)
4. **Prints a summary** grouped by protocol with actionable next steps

## Requirements

- [NetExec (nxc)](https://github.com/Penntest-dev/NetExec)
- Bash 4+
- `timeout` (coreutils)

## Installation

```bash
git clone https://github.com/HackingHusky/net-run.git
cd net-run
chmod +x net-run.sh
```

## Usage

### Basic — Single Target

```bash
# Password auth
./net-run.sh 10.10.10.5 admin Password123

# Pass-the-hash
./net-run.sh 10.10.10.5 administrator -H aad3b435b51404ee:deadbeefcafe1234

# With domain
./net-run.sh 10.10.10.5 jsmith 'P@ssw0rd' -d corp.local
```

### File-Based Inputs

```bash
# Spray users/passwords across targets
./net-run.sh -T targets.txt -U users.txt -P passes.txt -d corp.local

# Hash spray
./net-run.sh -T targets.txt -U users.txt -P hashes.txt -H -d corp.local
```

### Selective Protocols

```bash
# Only test SMB and RDP
./net-run.sh 10.10.10.5 admin Password123 -p smb,rdp

# MSSQL with local auth
./net-run.sh 10.10.10.5 sa Password123 -p mssql -L

# Subnet spray, WinRM only
./net-run.sh 192.168.1.0/24 admin Password123 -p winrm -d corp.local
```

## Options

| Flag | Description |
|------|-------------|
| `-T FILE` | Target list (one IP/CIDR per line) |
| `-U FILE` | Username list (one per line) |
| `-P FILE` | Password or hash list (one per line) |
| `-H` | Treat password as NTLM hash (pass-the-hash) |
| `-d DOMAIN` | Domain for authentication |
| `-L` | Force local auth on SMB/MSSQL |
| `-p PROTOS` | Comma-separated protocols (`smb,ldap,mssql,rdp,winrm,ftp,ssh,vnc,wmi`) |
| `-o DIR` | Output directory (default: `./net-run_results`) |
| `-E` | Skip auto-enumeration on successful auth |
| `-q` | Quiet mode — only show hits |

## Supported Protocols

| Protocol | Port(s) | Auto-Enum On Win |
|----------|---------|------------------|
| SMB | 445 | Shares, sessions, users, groups, disks, pass policy |
| LDAP | 389/636 | Users, groups, GMSA, delegation, AS-REP roast, Kerberoast |
| MSSQL | 1433 | Privilege check |
| RDP | 3389 | — |
| WinRM | 5985/5986 | — |
| FTP | 21 | — |
| SSH | 22 | — |
| VNC | 5900 | — |
| WMI | 135 | — |

## Output

Results are saved to `./net-run_results/` (or the directory set with `-o`):

```
net-run_results/
├── smb.txt              # Raw nxc output per protocol
├── ldap.txt
├── rdp.txt
├── ...
├── smb_enum.txt         # Auto-enum results (if auth succeeded)
├── smb_passpol.txt      # Password policy
├── ldap_enum.txt        # LDAP enumeration
├── asreproast.txt       # AS-REP roastable hashes (hashcat -m 18200)
├── kerberoast.txt       # Kerberoast hashes (hashcat -m 13100)
└── mssql_enum.txt       # MSSQL privilege info
```

## Example Output

```
  ═══ CREDENTIAL VALIDATION ═══
  [AUTH]  smb:   CORP\jsmith [+] authenticated
  [ADMIN] smb:   CORP\jsmith (Pwn3d!)
  [AUTH]  ldap:  CORP\jsmith [+] authenticated
  [AUTH]  winrm: CORP\jsmith [+] authenticated
  [AUTH]  rdp:   CORP\jsmith [+] authenticated

  ═══ AUTO-ENUMERATION ═══
  [*] SMB enum: shares, sessions, users, groups, disks...
  [*] LDAP enum: users, groups, gmsa, trusts...
  [+] Kerberoastable accounts found! → kerberoast.txt

  ═══════════════════════════════════════════
    RESULTS SUMMARY
  ═══════════════════════════════════════════

  Authenticated: 4    Admin/Pwn3d: 1

  ── ldap ──
    ✓ CORP\jsmith [+] authenticated
  ── rdp ──
    ✓ CORP\jsmith [+] authenticated
  ── smb ──
    ★ CORP\jsmith (Pwn3d!)
  ── winrm ──
    ✓ CORP\jsmith [+] authenticated

  Next steps:
    → SMB admin: secretsdump, SAM dump, lateral movement
    → WinRM: evil-winrm for interactive shell
    → RDP: xfreerdp for GUI access
    → LDAP: BloodHound collection, further AD enum
    → Kerberoast hashes found — crack with hashcat -m 13100
```

## Pairs Well With

- [husky-ad](https://github.com/HackingHusky/husky-ad) — Full AD enumeration & escalation toolkit
- [husky-privesc](https://github.com/HackingHusky/husky-privesc) — Cross-platform privilege escalation enumeration

## Author

**The Husky Hacker** — [thehuskyhacker.com](https://thehuskyhacker.com) | [GitHub](https://github.com/HackingHusky)
