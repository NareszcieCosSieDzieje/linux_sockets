# Arping implementation over ethernet.

# 1st ping is of type broadcast, the remaining pings are of type unicast to the resolved target MAC.

## Usage
- make arping
- sudo ./arping.elf INTERFACE_NAME (REQUIRED) TARGET_IP (REQUIRED) PING_COUNT (if <= 0 then endless else countdown) (OPTIONAL PARAM)
