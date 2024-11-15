If you are a stubborn Windows user ...

## Windows + VMware Setup

See: https://knowledge.broadcom.com/external/article/307369/using-a-network-adapter-only-with-the-vm.html

1. Plug int the network adapter and make sure Windows can see it
2. Navigate to "Network & Internet" > "Advanced Network Settings"
3. Find the USB ethernet adapter you just plugged in and edit > "more adapter options"
4. Turn off everything under the 'Networking' tab, except the VMware bridge protocol
-> this will ensure that windows can't touch the adapter anymore and it will only be visible to the linux guest through the bridgeing protocol.

Then shut off your VM if it isn't already off and change the network settings:

You need to assign the adapter to a bridged setting, beware that you may run into the issue that you cannot add a second bridged network if the autobridgeing (on net VM0) is turned on:
https://knowledge.broadcom.com/external/article/339372/workstation-fails-to-bridge-adapter-with.html

1. Navigate to edit > virtual Network editor
2. Change the settings of Vm0 to a physical adapter instead of autobridgeing. In my case I simply selected the network card (Intel(R) Wifi...)
3. Add another virtual network (between 2 and 7 to allow for bridging)
4. Change the newly added network to bridged and select the usb-ethernet adapter (In my case, TP-Link Ethernet...)
5. Apply the config and select OK.
6. In your virtual machine setting, add another network adapter and select the custom network you just added.

Now you can boot into your guest and check the configuration.


## Windows + Hyper-V setup:

Add a virtual switch in the network manager

it needs to be an external one that is connected to the ethernet adapter

Then add the additional network adapter to the VM and configure the DHCP server in your guest (automagically done by install and configure kea)
