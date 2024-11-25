DB_NAME = "mitm.db"

# Names of Network Interfaces - These will vary depending on the machine and network setup
INTERNET_IFACE = (
    "wlp9s0f0"  # e.g., "eth0" for Ethernet or "wlan0" for Wi-Fi.
)
AP_IFACE = (
    "wlp0s20f0u1u1"  # The interface your access point software uses.
)

# Access Point Configuration - Change these to your desired SSID and password
AP_SSID = "DummyHotspot"
AP_PASSWORD = "1234567890"

# MITMProxy Configuration
MITMPROXY_LISTEN_PORT = 8080  # The port MITMProxy listens on. Change if necessary.
# List of hosts (regex) that the proxy should ignore.
# Add or remove patterns according to your needs.
IGNORE_HOSTS_LIST = [
    r"(.*google\w*\.com)",
    r"(.*hcaptcha\.com)",
    r"(.*signalcaptchas\.org)",
    r"(.*gstatic\w*\.com)",
]

# Compiles the IGNORE_HOSTS_LIST into a single string, used in some configurations.
IGNORE_HOSTS = f'"{r"|".join(IGNORE_HOSTS_LIST)}"'
