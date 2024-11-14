{
  "Dhcp4": {
    "interfaces-config": {
      "interfaces": [ "$ap_interface" ]
    },
    "control-socket": {
      "socket-type": "unix",
      "socket-name": "/run/kea/kea4-ctrl-socket"
    },
    "lease-database": {
      "type": "memfile",
      "lfc-interval": 3600
    },
    "valid-lifetime": 600,
    "max-valid-lifetime": 7200,
    "subnet4": [
      {
        "id": 1,
        "subnet": "$ap4_subnet",
        "pools": [
          {
            "pool": "$dhcp_pool_range"
          }
        ],
        "option-data": [
          {
            "name": "routers",
            "data": "$dhcp_server_ip"
          },
          {
            "name": "domain-name-servers",
            "data": "192.168.1.1, 192.168.1.2"
          },
          {
            "name": "domain-name",
            "data": "mydomain.example"
          }
        ]
      }
    ]
  }
}