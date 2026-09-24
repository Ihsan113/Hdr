#!/system/bin/sh
MODDIR=${0%/*}
LOG=/data/local/tmp/danzku_pq_global_hook.log
echo "[$(date)] DanzKu PQ Global Hook v0.2" >> "$LOG"
PID="$(pidof vendor.mediatek.hardware.pq@2.2-service 2>/dev/null)"
echo "[$(date)] PQ service PID=${PID:-not-found}" >> "$LOG"
[ -x "$MODDIR/system/bin/danzku-pq-injector" ] && "$MODDIR/system/bin/danzku-pq-injector" --pid "${PID:-0}" --library "$MODDIR/system/lib64/libdanzku_pq.so" >> "$LOG" 2>&1
exit 0
