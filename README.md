# Minion in the Middle

Welcome! This is an open source framework for security researchers, facilitating conducting man-in-the-middle attacks against end-to-end encrypted messaging applications.
This is a research framework! We thus do not include any kind of obfuscation measures for attacks and will not accept contributions that attempt to add them.

While this repository currently focuses on the open-source Signal Messenger, we hope to extend it to more encrypted messenger applications in the future.

### Contributing

TODO

### License

TODO

### Table of Contents

<!-- TOC -->
* [Overview](#overview)
<!-- TOC -->

## Overview

We expect the following setup:

![setup](fig/high-level-hardware-setup.png)

**(A)** The **victim phone(s)** is connected to a dedicated hardware access point (AP) via a **Wifi link** **(B)**. 
The access point is connected to the laptop via an **ethernet link** **(C)** and an **ethernet-usb adapter** **(D)**.
The setup script (@see [network setup](setup/network.py)) expects a [Debian or Red Hat](setup/pm.py) based Linux operating system (tested on Fedora 40/41 and Ubuntu 24) and sets up a [kea DHCP4 server](https://www.isc.org/kea/) to provide
IP addresses to the AP and the **victim phone(s)** over the newly created interface. 

(If you happen to be a stubborn Windows user that is running Linux in a VM, check out [these docs](setup/Hypervisor_bridgeing.md) for
instructions on how to bridge the adapter interface through to your guest for both VMware and Hyper-V.)

Using dedicated hardware is the most stable way to create an additional networking interface on the **computer running the proxy**
**(E)** and thus the setup should *just work* independently of the hardware that was chosen. The setup finally also sets up the appropriate routing to forward traffic from the victim(s), to the proxy and finally NATs the traffic to the **internet** **(F)** through the machines default gateway.

### Configuration

We both constants and user set configuration parameters are defined in two yaml files in the [conf](conf) folder. We further use [Pydantic](https://docs.pydantic.dev/latest/) to define a hierarchy and validate types of parameters. This als includes default values and hints that you can look up [here](conf/config_spec.py) and will be picked up by IDEs.

Start by copying the [configuration example](conf/configuration.example.yml) as `conf/configuration.yml`. This file is user defined and should be listed in the [.gitignore](.gitignore).

Any value defined in the [constants](conf/constants.yml) can be redefined in the [configuration](conf/configuration.yml), where values of the configuration take precedent over parameters with the same hierarchy and name defined in the constants.

## Detailed Setup
#### Connecting the Access Point
First, check the interfaces on your machine and make note of the ones that are preexisting:
```
ip addr show
```
Then, power up your Access Point and connect it to the computer with the ethernet-USB adapter and repeat the command. Your machine should automatically detect the device, which will show up as an additional interface.

*Note:* If you are running a Linux VM on a Windows host, please refer to the following [additional documentation](setup/Hypervisor_bridgeing.md) to bridge the AP into your guest.

Once you've found the name of the new interface set it in the config file for the parameter `ap.interface`.

#### (optional) Configuring kea

Have a look at the `dhcp` and `kea` part of the configuration. Change it if necessary (e.g., you need a bigger pool of addresses or the subnet already conflicts with another interface on your machine). If you change the `dhcp` configuration, be aware that both the address pool and the `server_ip` must be part of the `subnet` and that the `server_ip` must not be contained in the address pool.
Please consult the [kea documentation](https://ubuntu.com/server/docs/how-to-install-and-configure-isc-kea) for more information.

### Run network setup

TODO: Refine once we have a cli.

Once the hardware is correctly detected by your machine and you have set all the configuration parameters, execute [setup_victim_ap](run.py).

If the script executes without error check that the `dhcp.server_ip` was correctly assigned to the `ap.iface`.
Check that the kea-server is running:
```
sudo systemctl status kea-dhcp4-server
```
And finally, you can sniff the interface to find the address that was assigned to the AP by the kea dhcp service. It will be contained in the DHCP pool range set in the configuration.
```
sudo tcpdump -i <ap.iface> ip
```
This address will allow you to connect to the management interface of your AP with a web browser. Please consult the manual of your hardware for more information.


### Operating the Minion

TODO

