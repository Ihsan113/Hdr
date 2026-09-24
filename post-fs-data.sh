#!/system/bin/sh
MODDIR=${0%/*}
chmod 755 "$MODDIR/service.sh" 2>/dev/null
chmod 755 "$MODDIR/system/bin/danzku-pq-injector" 2>/dev/null
chmod 755 "$MODDIR/system/bin/danzku-pq-status" 2>/dev/null
