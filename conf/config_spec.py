import ipaddress
from typing import List, Self

from pydantic import BaseModel, Field, model_validator


class APConfig(BaseModel):
    """
    Configuration for Access Point (AP).

    Attributes:
        iface: The network interface for the Access Point.
        pw: The password for accessing the AP.
        ssid: The Service Set Identifier (SSID) for the AP.
        internet_iface: The network interface that connects to the Internet.
    """

    iface: str = Field("ap1", description="Interface name, to be filled out")
    pw: str = Field("<PASSWORD>", description="Password to login")
    ssid: str = Field("evil-ap_5G", description="SSID, to be filled out")
    internet_iface: str = Field(
        "eth0",
        description='Name of your interface which connects to the internet, e.g., "eth0" for Ethernet or "wlan0" for Wi-Fi.',
    )


class DBConfig(BaseModel):
    """
    Configuration for the database.

    Attributes:
        name: The name of the SQLite database file.
    """

    name: str = Field("mitm_test.db", description="SQLite database name")


class DHCPConfig(BaseModel):
    """
    Configuration for DHCP settings.

    Attributes:
        pool_lower: The lower bound of the IP pool.
        pool_upper: The upper bound of the IP pool.
        server_ip: The IP address of the DHCP server.
        subnet: The subnet string, in CIDR notation.
    """

    pool_lower: ipaddress.IPv4Address | ipaddress.IPv6Address = ipaddress.ip_address(
        "10.8.8.80"
    )
    pool_upper: ipaddress.IPv4Address | ipaddress.IPv6Address = ipaddress.ip_address(
        "10.8.8.88"
    )
    server_ip: ipaddress.IPv4Address | ipaddress.IPv6Address = Field(
        ipaddress.ip_address("10.8.8.1"),
        description="must be contained in subnet and be outside of pool range",
    )
    subnet: ipaddress.IPv4Network | ipaddress.IPv6Address = Field(
        ipaddress.ip_network("10.8.8.0/24")
    )

    @model_validator(mode="after")
    def check_network_configuration(self) -> Self:
        server_ip = self.server_ip
        pool_lower = self.pool_lower
        pool_upper = self.pool_upper
        subnet = self.subnet

        if server_ip not in subnet:
            raise ValueError(
                f"server_ip {server_ip} must be contained in the subnet {subnet}"
            )

        if pool_lower <= server_ip <= pool_upper:
            raise ValueError(
                f"server_ip {server_ip} must be outside the pool range {pool_lower} to {pool_upper}"
            )

        return self


class KeaConfig(BaseModel):
    """Configuration for Kea DHCP service.

    Attributes:
          api_pw: The API password for Kea.
          pw_filepath: The file path to the Kea API password file.
          systemd_service: The name of the systemd service for Kea.
    """

    api_pw: str = "Meep"
    pw_filepath: str = "/etc/kea/kea-api-password"
    systemd_service: str = "kea-dhcp4"


class MitmproxyConfig(BaseModel):
    """
    Configuration for mitmproxy settings.

    Attributes:
        listen_port: The port on which mitmproxy runs.
        ignore_hosts_list: A list of hosts to ignore.

    Methods:
        ignore_hosts: Constructs a regex pattern string from the list of ignored hosts.
    """

    listen_port: int = 8080
    ignore_hosts_list: List[str] = Field(
        default_factory=lambda: ["TODO", "TODO", "..."]
    )

    @property
    def ignore_hosts(self) -> str:
        """Compute the regex of hosts to ignore."""
        return rf'"{r"|".join(self.ignore_hosts_list)}"'


class SignalConfig(BaseModel):
    """
    Configuration for Signal settings.

    Attributes:
        prod_server: The production server URL.
        stage_server: The staging server URL.
        version: can be removed later
    """

    prod_server: str = "chat.signal.org"
    stage_server: str = "chat.staging.signal.org"
    version: int = 42


class Config(BaseModel):
    """Main configuration object."""

    ap: APConfig = APConfig()
    db: DBConfig = DBConfig()
    dhcp: DHCPConfig = DHCPConfig()
    kea: KeaConfig = KeaConfig()
    mitmproxy: MitmproxyConfig = MitmproxyConfig()
    signal: SignalConfig = SignalConfig()
