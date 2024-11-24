If you are a stubborn Windows use running an Ubuntu VM in some hypervisor -- yes Chrissy we mean you :) -- here are some docs to help you out of the obvious conundrums:

This applies to the Ethernet adapter + AP hardware setup.

### Beware that a disconnected adapter is likely to lead to a silent failure on the AP interface, and that unplugging the adapter may necessitate that you to follow these steps again.

## Hyper-V setup:

You must connect the ethernet adapter to a virtual switch in the hyper-v network manager.

1. Plug in the netowork adapter and check that Windows detects it correctly.
2. Navigate to the "Virtual Switch Manager..." in Hyper-V (right hand side under "Actions")
3. Create a new virtual switch of type "External"
4. Name it something recognizable 
5. Choose the ethernet adapter from the drop-down menu under "External Network".
5. Navigate to your VM settings (right click on the VM > settings) and under "Add Hardware" add an additional Network adapter
6. Choose the adapter you named before from the drop-down menu and apply

***Note: You may only need to repeat step 5 after setting it up once.***

## VMware Setup

For additional context, see [Using a Network Adapter Only with the VM](https://knowledge.broadcom.com/external/article/307369/using-a-network-adapter-only-with-the-vm.html)

1. Plug int the network adapter and make sure Windows can see it
2. Navigate to "Network & Internet" > "Advanced Network Settings"
3. Find the USB ethernet adapter you just plugged in and edit > "more adapter options"
4. Turn off everything under the 'Networking' tab, except the VMware bridge protocol
   > This ensures Windows can't access the adapter, making it visible only to the Linux guest through the bridging protocol.

Then shut off your VM if it isn't already off and change the network settings:

You need to assign the adapter to a bridged setting. Note that you may not be able to add a second bridged network if auto-bridging is enabled on VM0. See [Workstation Fails to Bridge Adapter](https://knowledge.broadcom.com/external/article/339372/workstation-fails-to-bridge-adapter-with.html) for details.

1. Navigate to edit > virtual Network editor
2. Change the settings of VM0 to a physical adapter instead of auto-bridging. For example, select your network card (e.g., Intel(R) Wifi...)
3. Add another virtual network (between 2 and 7 to allow for bridging)
4. Change the newly added network to bridged and select the usb-ethernet adapter (In my case, TP-Link Ethernet...)
5. Apply the config and select OK.
6. In your virtual machine setting, add another network adapter and select the custom network you just added.

Finally, boot into your guest and verify the configuration.
