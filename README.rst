uBridge
=======

uBridge is a simple application to create user-land bridges between various technologies.
Currently bridging between UDP tunnels, Ethernet and TAP interfaces is supported.
Packet capture is also supported.

Dependencies:

- pcap library (wincap on Windows).
- pthread library.

Basic usage: create a file named `ubridge.ini` in the same directory as uBridge and then start it.

Example of content:

.. code:: bash

    ; bridge Ethernet interface eth0 with an UDP tunnel
    [bridge0]
    source_ethernet = eth0
    destination_udp = 10000:127.0.0.1:10001 ; syntax is local_port:remote_host:remote_port

    ; bridge TAP interface tap0 with an UDP tunnel
    ; and capture packets to /tmp/bridge1.pcap
    [bridge1]
    source_tap = tap0
    destination_udp = 11000:127.0.0.1:11001
    pcap_file = /tmp/bridge1.pcap
    pcap_protocol = EN10MB ; PCAP data link type, default is EN10MB

    ; it is even possible to bridge two UDP tunnels and capture!
    [bridge2]
    source_udp = 40000:127.0.0.1:40001
    destination_udp = 50000:127.0.0.1:50001
    pcap_file = /tmp/bridge2.pcap

    ; or to bridge 2 interfaces
    [bridge3]
    source_tap = tap0
    destination_ethernet = vmnet2

On Linux you can use a RAW socket to bridge an Ethernet interface (a bit faster than with the default PCAP method).

.. code:: bash

    ; bridge Ethernet interface eth0 with an UDP tunnel
    ; using the RAW socket method (Linux rocks!)
    [bridge4]
    source_linux_raw = eth0
    destination_udp = 42000:127.0.0.1:42001

A few notes:

- A Bridge name (e.g. bridge4) can be anything as long it is unique in the same file.
- Capabitilies must be set on the executable (Linux only) or you must have administrator rights to bridge Ethernet or TAP interfaces.
- It is only possible to bridge two interfaces/tunnels together. uBridge is not a hub or a switch!
