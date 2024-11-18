# Minion in the Middle

Welcome! This is an open source framework aimed at security researchers to facilitate conducting man-in-the-middle attacks against end-to-end encrypted messaging applications.
This is for testing purposes only and we thus do not include any obfuscation measures of the attack.

While this repository currently focusses on the open-source Signal Messenger, we plan to extend it to more applications in the future.


## Setup

We currently support the following setup:

![setup](fig/high-level-hardware-setup.png)

From left to right:

The **victim phone(s)** is connected to an access point via a **Wifi link** over a dedicated Hardware access point. The access point is connected to the laptop via an ethernet link and an ethernet-usb adapter.
The setup script (@see [network setup](setup/network.py)) expects a Linux operating system (tested on Fedora 40/41 and Ubuntu 24) and sets up a kea DHCP server to provide
connectivity through the access point interface.

(If you happen to be a stubborn Windows user that is runing Linux in a VM, check out [these docs](setup/Hypervisor_bridgeing.md) for
instructions on how to bridge the AP through to your guest for both VMware and Hyper-V.)