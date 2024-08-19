DB_NAME = "mitm.db"

INTERNET_IFACE = "wlp0s20f3"
AP_IFACE = "wlp0s20f0u5u1"  # TODO: Change this to the actual AP interface

AP_SSID = "DummyHotspot"
AP_PASSWORD = "1234567890"

MITMPROXY_LISTEN_PORT = 8080
IGNORE_HOSTS_LIST = [
    r"(.*google\w*\.com)",
    r"(.*hcaptcha\.com)",
    r"(.*signalcaptchas\.org)",
]
IGNORE_HOSTS = f'"{r"|".join(IGNORE_HOSTS_LIST)}"'
