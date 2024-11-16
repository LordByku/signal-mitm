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
            # in principle, this could be using the local dns resolver but let's keep it simple for now
            "data": "9.9.9.9, 1.1.1.1, 8.8.8.8"
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