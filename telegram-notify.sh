#!/bin/bash

# Telegram Bot Configuration
# Replace these with your actual bot token and chat ID
BOT_TOKEN="YOUR_TELEGRAM_BOT_TOKEN"
CHAT_ID="YOUR_TELEGRAM_CHAT_ID"

NAME="$1"
TYPE="$2"
STILL_MET="$3"
VALUE="$4"

# Helper function to intelligently format bytes to human-readable strings
format_bytes() {
    local bytes=$1
    if [ -z "$bytes" ]; then echo "0 B"; return; fi
    local units=(B KB MB GB TB PB)
    local unit=0
    while [ "$bytes" -gt 1024 ] && [ "$unit" -lt 5 ]; do
        bytes=$((bytes / 1024))
        unit=$((unit + 1))
    done
    echo "$bytes ${units[$unit]}"
}

# Format the raw VALUE based on the alert TYPE
format_value() {
    local val=$1
    case "$TYPE" in
        "CPU_USAGE"|"CPU_IOWAIT"|"CPU_STEAL"|"RAM_USAGE"|"SWAP_USAGE"|"DISK_USAGE") echo "${val}%" ;;
        "NET_RX"|"NET_TX"|"DISK_READ"|"DISK_WRITE") echo "$(format_bytes $val)/s" ;;
        "TRAFFIC_TOTAL"|"TRAFFIC_RX"|"TRAFFIC_TX") echo "$(format_bytes $val)" ;;
        "LATENCY") echo "${val} ms" ;;
        "DOWN") echo "$((val / 60)) minutes" ;;
        "EXPIRE") date -d @"$val" '+%Y-%m-%d' 2>/dev/null || echo "timestamp $val" ;;
        *) echo "$val" ;;
    esac
}

FORMATTED_VALUE=$(format_value "$VALUE")

if [ "$STILL_MET" = "TRUE" ]; then
    subject="🚨 <b>$TYPE</b> threshold exceeded"
    message="Alert condition <b>$TYPE</b> detected for <b>$NAME</b>."
    [ -n "$VALUE" ] && message="$message<br>Current value: <b>$FORMATTED_VALUE</b>"
else
    subject="✅ <b>$TYPE</b> threshold no longer exceeded"
    message="Alert condition <b>$TYPE</b> resolved for <b>$NAME</b>."
    [ -n "$VALUE" ] && message="$message<br>Current value: <b>$FORMATTED_VALUE</b>"
fi

if [ "$TYPE" = "DOWN" ]; then
    if [ "$STILL_MET" = "TRUE" ]; then
        subject=""
        message="🔴 <b>$NAME</b> is now DOWN for $FORMATTED_VALUE."
    else
        subject=""
        message="🟢 <b>$NAME</b> is now UP."
    fi
fi

if [ -z "$subject" ]; then
    txt="$message"
else 
    txt="$subject"$'\n\n'"$message"
fi

curl --max-time 20 -s -X POST "https://api.telegram.org/bot${BOT_TOKEN}/sendMessage" \
    -d chat_id="${CHAT_ID}" \
    -d parse_mode="HTML" \
    --data-urlencode text="$txt" > /dev/null