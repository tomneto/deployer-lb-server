#!/usr/bin/env bash
# swap-lib.sh — sourceable swap/cache functions shared by setup.sh (provisioning
# time) and swapctl.sh (runtime control, invoked over SSH by selfApi). No
# side effects on source — every side-effecting action lives in a function.
#
# Callers are expected to already have `log()`/`die()`/`have()` defined
# (setup.sh does); swapctl.sh defines minimal fallbacks below when sourced
# standalone.

if ! declare -F have >/dev/null 2>&1; then
    have() { command -v "$1" >/dev/null 2>&1; }
fi
if ! declare -F log >/dev/null 2>&1; then
    log() { printf '[swap-lib] %s\n' "$*" >&2; }
fi
if ! declare -F die >/dev/null 2>&1; then
    die() { log "ERROR: $*"; exit 1; }
fi

SWAP_FILE="${SWAP_FILE:-/swapfile}"

# One-line RAM/swap snapshot for logs — same shape as setup.sh's mem_snapshot.
mem_snapshot() {
    awk '/^MemTotal:/{t=$2} /^SwapTotal:/{s=$2} /^MemAvailable:/{a=$2}
         END{printf "RAM=%dMB swap=%dMB avail=%dMB", t/1024, s/1024, a/1024}' \
        /proc/meminfo
}

# JSON snapshot of RAM/swap/swapfile state, for `swapctl status` and for
# selfApi's swap_control.py to parse.
swap_snapshot_json() {
    local total_kb swap_kb avail_kb swap_used_kb file_size_kb=0
    total_kb="$(awk '/^MemTotal:/{print $2}' /proc/meminfo)"
    swap_kb="$(awk '/^SwapTotal:/{print $2}' /proc/meminfo)"
    avail_kb="$(awk '/^MemAvailable:/{print $2}' /proc/meminfo)"
    swap_used_kb="$(awk '/^SwapTotal:/{t=$2} /^SwapFree:/{f=$2} END{print t-f}' /proc/meminfo)"
    if [[ -f "$SWAP_FILE" ]]; then
        file_size_kb=$(( $(stat -c%s "$SWAP_FILE" 2>/dev/null || echo 0) / 1024 ))
    fi
    printf '{"ram_total_mb":%d,"swap_total_mb":%d,"swap_used_mb":%d,"available_mb":%d,"swapfile_path":"%s","swapfile_size_mb":%d}\n' \
        "$(( total_kb / 1024 ))" "$(( swap_kb / 1024 ))" "$(( swap_used_kb / 1024 ))" \
        "$(( avail_kb / 1024 ))" "$SWAP_FILE" "$(( file_size_kb / 1024 ))"
}

# Ensure total RAM+swap is at least $1 KB, topping up or creating $SWAP_FILE
# as needed. This is the exact logic setup.sh's ensure_swap() used to inline,
# now parameterized so setup.sh can call `swap_ensure_floor $((8*1024*1024))`
# with unchanged behavior.
swap_ensure_floor() {
    local floor_kb="$1"
    have swapon || return 0  # no swap support on this system, nothing to do
    local total_kb swap_kb
    total_kb="$(awk '/^MemTotal:/{print $2}' /proc/meminfo)"
    swap_kb="$(awk '/^SwapTotal:/{print $2}' /proc/meminfo)"
    if (( total_kb + swap_kb >= floor_kb )); then
        log "RAM+swap already sufficient ($(mem_snapshot)) — no swapfile action needed"
        return 0
    fi
    local shortfall_kb=$(( floor_kb - total_kb - swap_kb ))
    local shortfall_mb=$(( (shortfall_kb + 1023) / 1024 ))
    local avail_kb; avail_kb="$(df -Pk / | awk 'NR==2{print $4}')"
    if (( avail_kb < shortfall_kb + 512 * 1024 )); then
        log "warning: RAM+swap below floor ($(mem_snapshot)) and disk too tight for a ${shortfall_mb}MB swapfile — skipping"
        return 0
    fi
    local own_old_kb=0
    if [[ -f "$SWAP_FILE" ]]; then
        own_old_kb=$(( $(stat -c%s "$SWAP_FILE" 2>/dev/null || echo 0) / 1024 ))
        log "topping up existing $SWAP_FILE (RAM+swap was $(mem_snapshot), below floor) by ${shortfall_mb}MB"
        swapoff "$SWAP_FILE" 2>/dev/null || true
        rm -f "$SWAP_FILE"
    else
        log "RAM+swap below floor ($(mem_snapshot)) — creating ${shortfall_mb}MB swapfile at $SWAP_FILE"
    fi
    local new_size_mb=$(( (own_old_kb + shortfall_kb + 1023) / 1024 ))
    if fallocate -l "${new_size_mb}M" "$SWAP_FILE" 2>/dev/null || dd if=/dev/zero of="$SWAP_FILE" bs=1M count="$new_size_mb" 2>/dev/null; then
        chmod 600 "$SWAP_FILE"
        mkswap "$SWAP_FILE" >/dev/null \
            && swapon "$SWAP_FILE" \
            && grep -q "^${SWAP_FILE} " /etc/fstab 2>/dev/null || echo "${SWAP_FILE} none swap sw 0 0" >>/etc/fstab
        log "swapfile active: $(swapon --show=NAME,SIZE --noheadings 2>/dev/null | tr '\n' ' ') — $(mem_snapshot)"
    else
        log "warning: could not create $SWAP_FILE — proceeding without extra swap ($(mem_snapshot))"
    fi
}

# Resize $SWAP_FILE to exactly $1 MB (swapoff + recreate). Validates disk
# headroom the same way swap_ensure_floor does.
swap_resize() {
    local target_mb="$1"
    [[ "$target_mb" =~ ^[0-9]+$ ]] || die "swap_resize: size must be a positive integer (MB), got '$target_mb'"
    have swapon || die "swap_resize: swapon not available on this system"

    local old_size_kb=0
    if [[ -f "$SWAP_FILE" ]]; then
        old_size_kb=$(( $(stat -c%s "$SWAP_FILE" 2>/dev/null || echo 0) / 1024 ))
    fi
    local target_kb=$(( target_mb * 1024 ))
    local needed_kb=$(( target_kb > old_size_kb ? target_kb - old_size_kb : 0 ))
    local avail_kb; avail_kb="$(df -Pk / | awk -v f="$SWAP_FILE" '$0 !~ f {print}' | awk 'NR==2{print $4}')"
    [[ -n "$avail_kb" ]] || avail_kb="$(df -Pk / | awk 'NR==2{print $4}')"
    if (( avail_kb < needed_kb + 256 * 1024 )); then
        die "swap_resize: not enough disk headroom for a ${target_mb}MB swapfile ($(mem_snapshot), avail=${avail_kb}KB)"
    fi

    log "resizing $SWAP_FILE to ${target_mb}MB (was $(( old_size_kb / 1024 ))MB)"
    swapoff "$SWAP_FILE" 2>/dev/null || true
    rm -f "$SWAP_FILE"
    if fallocate -l "${target_mb}M" "$SWAP_FILE" 2>/dev/null || dd if=/dev/zero of="$SWAP_FILE" bs=1M count="$target_mb" 2>/dev/null; then
        chmod 600 "$SWAP_FILE"
        mkswap "$SWAP_FILE" >/dev/null || die "swap_resize: mkswap failed"
        swapon "$SWAP_FILE" || die "swap_resize: swapon failed"
        grep -q "^${SWAP_FILE} " /etc/fstab 2>/dev/null || echo "${SWAP_FILE} none swap sw 0 0" >>/etc/fstab
        log "swapfile resized: $(swapon --show=NAME,SIZE --noheadings 2>/dev/null | tr '\n' ' ') — $(mem_snapshot)"
    else
        die "swap_resize: could not (re)create $SWAP_FILE at ${target_mb}MB"
    fi
}

# Turn off and remove $SWAP_FILE, cleaning up its fstab entry.
swap_remove() {
    have swapon || die "swap_remove: swapon not available on this system"
    [[ -f "$SWAP_FILE" ]] || { log "swap_remove: $SWAP_FILE does not exist, nothing to do"; return 0; }
    swapoff "$SWAP_FILE" || die "swap_remove: swapoff failed — swap may be in active use"
    rm -f "$SWAP_FILE"
    if [[ -w /etc/fstab ]]; then
        sed -i "\|^${SWAP_FILE} |d" /etc/fstab
    fi
    log "removed $SWAP_FILE — $(mem_snapshot)"
}

# Drop OS page/dentry/inode caches. level: 1=pagecache 2=dentries+inodes 3=all
drop_caches() {
    local level="${1:-3}"
    [[ "$level" =~ ^[1-3]$ ]] || die "drop_caches: level must be 1, 2 or 3, got '$level'"
    [[ -w /proc/sys/vm/drop_caches ]] || die "drop_caches: /proc/sys/vm/drop_caches not writable (need root)"
    sync
    echo "$level" >/proc/sys/vm/drop_caches
    log "dropped caches (level=$level) — $(mem_snapshot)"
}
