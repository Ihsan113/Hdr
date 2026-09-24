#!/system/bin/sh
MODDIR=${0%/*}
LOG=/sdcard/DanzKu_PQ_Global_Hook.txt

log_txt() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >> "$LOG"
}

log_txt "========================================"
log_txt "DanzKu PQ Global Hook v0.2"
log_txt "Service started"

PID="$(pidof vendor.mediatek.hardware.pq@2.2-service 2>/dev/null)"
log_txt "PQ service PID=${PID:-not-found}"

if [ -x "$MODDIR/system/bin/danzku-pq-injector" ]; then
    log_txt "Starting injector"
    "$MODDIR/system/bin/danzku-pq-injector" \
        --pid "${PID:-0}" \
        --library "$MODDIR/system/lib64/libdanzku_pq.so" \
        --log "$LOG" >> "$LOG" 2>&1
    RC=$?
    log_txt "Injector exit code=$RC"
else
    log_txt "ERROR: injector not found"
fi

log_txt "Service finished"
log_txt "========================================"
exit 0
