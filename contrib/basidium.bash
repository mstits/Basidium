# Bash completion for basidium
#
# Install:
#   sudo cp contrib/basidium.bash /etc/bash_completion.d/basidium
# or source it from ~/.bashrc:
#   source /path/to/Basidium/contrib/basidium.bash

_basidium() {
    local cur prev words cword
    _init_completion 2>/dev/null || {
        cur="${COMP_WORDS[COMP_CWORD]}"
        prev="${COMP_WORDS[COMP_CWORD-1]}"
        words=("${COMP_WORDS[@]}")
        cword=$COMP_CWORD
    }

    local modes="mac arp dhcp pfc nd lldp stp igmp"
    local payloads="zeros ff dead incr"

    local long_opts="
        --selftest --pcap-out --pcap-replay --tui --nccl --nccl-binary
        --duration --profile --vlan-pcp --pfc-priority --pfc-quanta
        --sweep --report --burst --vlan-range --detect --qinq --payload
        --version --dry-run --scenario
        --validate --print-config --list-modes --list-profiles
        --seed --ndjson --csv --report-compact
        --stop-on-failopen --stop-on-degradation
        --diff --diff-threshold-pps --diff-threshold-busbw
        --json --help"

    local short_opts="-i -M -t -r -J -L -A -S -T -l -v -n -R -U -V -h"

    case "$prev" in
        -M)
            COMPREPLY=( $(compgen -W "$modes" -- "$cur") )
            return 0
            ;;
        --payload)
            COMPREPLY=( $(compgen -W "$payloads" -- "$cur") )
            return 0
            ;;
        -i)
            # Network interfaces (Linux: /sys/class/net; macOS: ifconfig)
            local ifs
            if [[ -d /sys/class/net ]]; then
                ifs=$(ls /sys/class/net 2>/dev/null)
            else
                ifs=$(ifconfig -l 2>/dev/null)
            fi
            COMPREPLY=( $(compgen -W "$ifs" -- "$cur") )
            return 0
            ;;
        --profile)
            # Mirror profiles_dir() resolution order: explicit override, then
            # legacy ~/.basidium when present, else the XDG config dir.
            local pdir
            if [[ -n "${BASIDIUM_PROFILE_DIR:-}" ]]; then
                pdir="$BASIDIUM_PROFILE_DIR"
            elif [[ -d "$HOME/.basidium" ]]; then
                pdir="$HOME/.basidium"
            elif [[ -n "${XDG_CONFIG_HOME:-}" ]]; then
                pdir="$XDG_CONFIG_HOME/basidium"
            else
                # Matches profiles_dir(): with no XDG_CONFIG_HOME the C code
                # falls back to the legacy ~/.basidium, not ~/.config.
                pdir="$HOME/.basidium"
            fi
            local names
            names=$(ls "$pdir"/*.conf 2>/dev/null \
                    | xargs -n1 basename 2>/dev/null \
                    | sed 's/\.conf$//')
            COMPREPLY=( $(compgen -W "$names" -- "$cur") )
            return 0
            ;;
        --scenario|--validate)
            COMPREPLY=( $(compgen -f -X '!*.tco' -- "$cur") \
                       $(compgen -d -- "$cur") )
            return 0
            ;;
        --pcap-out|--pcap-replay)
            COMPREPLY=( $(compgen -f -X '!*.pcap' -- "$cur") \
                       $(compgen -d -- "$cur") )
            return 0
            ;;
        --report|--csv|--diff|--nccl-binary|-l)
            COMPREPLY=( $(compgen -f -- "$cur") )
            return 0
            ;;
    esac

    if [[ "$cur" == --* ]]; then
        COMPREPLY=( $(compgen -W "$long_opts" -- "$cur") )
    elif [[ "$cur" == -* ]]; then
        COMPREPLY=( $(compgen -W "$long_opts $short_opts" -- "$cur") )
    fi
} && complete -F _basidium basidium
