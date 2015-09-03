uBridge
=======

uBridge is a simple application to create user-land bridges between various technologies.
Currently bridging between UDP tunnels, Ethernet and TAP interfaces is supported.
Packet capture is also supported.

Dependencies:

- pcap library (wincap on Windows).
- pthread library.

Hypervisor mode
---------------

The hypervisor mode of uBridge allows you to dynamically
add and remove bridges.

You can connect directly to the TCP control port with telnet.

Usage: ubridge -H [<ip_address>:]<tcp_port>

The command syntax is simple: <module> <function> [arguments...]
For example: "bridge create test" creates a bridge named "test".

The modules that are currently defined are given below:

* hypervisor   : General hypervisor management
* bridge       : bridges management
* docker       : Docker veth management

**Hypervisor module ("hypervisor")**

* "hypervisor version" : Display the version of dynamips.

.. code:: bash

    hypervisor version
    100-0.9.1

* "hypervisor module_list" : Display the module list.

.. code:: bash

    101 bridge
    101 hypervisor
    100-OK

* "hypervisor cmd_list <module>" : Display commands recognized by the specified module.

.. code:: bash

    hypervisor cmd_list bridge
    101 list (min/max args: 0/0)
    101 stop_capture (min/max args: 1/1)
    101 start_capture (min/max args: 2/3)
    101 add_nio_linux_raw (min/max args: 2/2)
    101 add_nio_ethernet (min/max args: 2/2)
    101 add_nio_tap (min/max args: 2/2)
    101 add_nio_udp (min/max args: 4/4)
    101 rename (min/max args: 2/2)
    101 stop (min/max args: 1/1)
    101 start (min/max args: 1/1)
    101 delete (min/max args: 1/1)
    101 create (min/max args: 1/1)
    100-OK

* "hypervisor close" : Close the current session.

.. code:: bash

    hypervisor close
    100-OK
    Connection closed by foreign host.

* "hypervisor stop"  : Destroy all objects and stop hypervisor.

.. code:: bash

    hypervisor stop
    100-OK
    Connection closed by foreign host.

* "hypervisor reset" : Destroy all objects. (used to get an empty configuration)

.. code:: bash

    hypervisor reset
    100-OK

**Bridge module ("bridge")**

* "bridge create <bridge_name>" : Create a new bridge.

.. code:: bash

    bridge create br0
    100-bridge 'br0' created

* "bridge list" : List all exiting Bridges.

.. code:: bash

    bridge list
    101 br0 (NIOs = 0)
    100-OK

* "bridge delete <bridge_name>" : Delete a bridge.

.. code:: bash

    bridge delete br0
    100-bridge 'br0' deleted

* "bridge start <bridge_name>" : Start a bridge.
  A bridge must have 2 NIOs added in order to start.

.. code:: bash

    bridge start br0
    100-bridge 'br0' started

* "bridge stop <bridge_name>" : Stop a bridge.

.. code:: bash

    bridge stop br0
    100-bridge 'br0' stopped

* "bridge rename <old_bridge_name> <new_bridge_name>" : Rename a bridge.

.. code:: bash

    bridge rename br0 br1
    100-bridge 'br0' renamed to 'br1'

* "bridge add_nio_udp <bridge_name> <local_port> <remote_host> <remote_port>" :
  Add an UDP NIO with the specified parameters to a bridge.

.. code:: bash

    bridge add_nio_udp br0 20000 127.0.0.1 30000
    100-NIO UDP added to bridge 'br0'

* "bridge add_nio_tap <bridge_name> <tap_device>" :
  Add an TAP NIO to a bridge. TAP devices are supported only on Linux and FreeBSD and require root access.

.. code:: bash

    bridge add_nio_tap br0 tap0
    100-NIO TAP added to bridge 'br0'

* "bridge add_nio_ethernet <bridge_name> <eth_device>" :
  Add a generic Ethernet NIO to a bridge, using PCAP (0.9.4 and greater). It requires root access.

.. code:: bash

    bridge add_nio_ethernet br0 eth0
    100-NIO Ethernet added to bridge 'br0'

* "bridge add_nio_linux_raw <bridge_name> <eth_device>" :
  Add a Linux RAW Ethernet NIO. It requires root access and is supported only on Linux platforms.

.. code:: bash

    bridge add_nio_linux_raw br0 eth0
    100-NIO Linux raw added to bridge 'br0'

* "bridge start_capture <bridge_name> <pcap_file> [pcap_linktype]" :
  Start a PCAP packet capture on a bridge. PCAP link type default is Ethernet "EN10MB".

.. code:: bash

    bridge start_capture br0 "/tmp/my_capture.pcap"
    100-packet capture started on bridge 'br0'

* "bridge stop_capture <bridge_name>" :
  Stop a PCAP packet capture on a bridge.

.. code:: bash

    bridge stop_capture br0
    100-packet capture stopped on bridge 'br0'

**Docker module ("docker")**

* "docker create_veth <interface_name_1> <interface_name_2>" :
  Create virtual Ethernet interface pair.

.. code:: bash

    docker create_veth hostif guestif
    100-veth pair created: hostif and guestif

* "docker move_to_ns <namespace_id>" :
  Move Ethernet interface to network namespace.

.. code:: bash

    docker move_to_ns guestif 6367
    100-guestif moved to namespace 6367

* "docker delete_veth <interface_name>" :
  Delete virtual Ethernet interface.

.. code:: bash

    docker delete_veth hostif
    100-veth interface hostif has been deleted

**Session example**

This will bridge a tap0 interface to an UDP tunnel.

Start the hypervisor:

.. code:: bash
    
    user@host# ./ubridge -H 2232
    Hypervisor TCP control server started (port 2232).


Connect via telnet:

.. code:: bash

    user@host# telnet localhost 2232


.. code:: bash

    bridge create br0
    100-bridge 'br0' created

    bridge start br0
    209-bridge 'br0' must have 2 NIOs to be started

    bridge add_nio_tap br0 tap0
    100-NIO TAP added to bridge 'br0'

    bridge add_nio_udp br0 20000 127.0.0.1 30000
    100-NIO UDP added to bridge 'br0'

    bridge start br0
    100-bridge 'br0' started

Config file mode
----------------

Usage: create a file named ubridge.ini in the same directory as uBridge and then start the executable.

Signal SIGHUP (not available on Windows) can be used to reload the config file.

Example of content:

.. code:: ini

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

.. code:: ini

    ; bridge Ethernet interface eth0 with an UDP tunnel
    ; using the RAW socket method (Linux rocks!)
    [bridge4]
    source_linux_raw = eth0
    destination_udp = 42000:127.0.0.1:42001

On Windows, interfaces must be specified with the NPF notation. You can display all available network devices
using ubridge.exe -e on a command line.

.. code:: ini

    ; using a Windows NPF interface
    [bridge5]
    source_ethernet = "\Device\NPF_{BC46623A-D65B-4498-9073-96B9DC4C8CBA}"
    destination_udp = 10000:127.0.0.1:10001

Notes
-----

- A Bridge name (e.g. bridge4) can be anything as long it is unique in the same file or inside the hypervisor.
- Capabitilies must be set on the executable (Linux only) or you must have administrator rights to bridge Ethernet or TAP interfaces.
- It is only possible to bridge two interfaces/tunnels together. uBridge is not a hub or a switch!
