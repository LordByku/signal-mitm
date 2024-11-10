https://documentation.ubuntu.com/server/how-to/networking/install-isc-kea/

Add the interface pointing towards the victim to this config file:
/etc/kea/kea-dhcp4.conf

=> copy the example config file and choose a private subnet, make sure you also set up one 
of the addressed on the interface as the router.

Example config file:

# TODO

Example interface setup:

# TODO

=> consider scripting some of this (e.g., setting up the router addr from the config file)

ip addr add 10.8.8.1/24 dev ens37

Don't forget to reload the stupid kea server after touching the stupid config gruuuuump!!!!!

systemctl restart kea-dhcp4-server

