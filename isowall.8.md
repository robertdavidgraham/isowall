isowall(8) -- Simplistic isolating firewall
===========================================

## SYNOPSIS

isowall --conf <file.conf>

## DESCRIPTION

**isowall** is a stupid simpled firewall for isolating a hostile machine
from the local network, but still provide it access to the Internet.
This is useful for studying viruses, or setting up open WiFi access-points.

The primary feature of this program is that it doesn't integrate with the
local machine's TCP/IP stack, but instead, can only be used on network
adapters without a network stack bound to them. This drastically reduces
the attack surface exposed to hostile attack.

## OPTIONS

Everything can be set on the command-line prefixed with `--`, or within
a configuration file without the `--` prefix, but with a `=` between
the name and value.

  * `--internal-ifname <if>`: The name of the network adapter that is
    connected to the hostile device that is to be isolated. A common
	example would be something like `eth1`. This network adapter must
	not already be used for networking, or the program will fail.

  * `--internal-target-ip <ip>`: The IPv4 address of the hostile machine.
    This program only accepts outbound packets from this one IP address,
	or inbound packets destined to this IP adress.

  * `--internal-target-mac <mac>`: The MAC address (also known as 
    Etherent address) of the hostile machine that is being isolated.
	For best security, this should be manually configured. If not, it
	will be auto-discovered by ARPing the target's IP address.

  * `--internal-my-mac`: The MAC address of the adapter used for the
    internal network. If not manually configured, it will automatically
	be detected. This is used to verify that no other program is using
	the network adapter except for this program.

  * `--external-ifname <if>`: The name of the network adapter that is
    on the Internet-side of the firewall. Ideally, this network adapter
	should not be used for any other purpose. In some cases, the primary
	network adapter (like `eth0`) may be used, in which case the parameter
	`--reuse-external` must be specified, or the program will fail.

  * `--external-router-ip <ip>`: The IP address of the local
    router that will forward packets to the Internet. This is needed for
	filtering ARP packets, to make sure that the hostile device can
	only ARP for the router's IP address.

  * `--external-target-mac <mac>`: The MAC address (also known as 
    Etherent address) of the external router. For best security, 
	this should be manually configured. If not, it
	will be auto-discovered by ARPing the router's IP address.

  * `--external-my-mac`: The MAC address of the adapter used for the
    external network. If not manually configured, it will automatically
	be detected. This is used to verify that no other program is using
	the network adapter except for this program. If you want to share
	the extenral network adapter with other programs on the machine,
	you must specified `--reuse-external`.

  * `--conf <filename>`: Reads in a configuration file. The
    format of the configuration file is described below. By default,
	the program will attempt to read `/etc/isowall.conf`.


  * `--echo`: Don't run, but instead dump the current configuration to a file.
    This file can then be used with the `--conf` option. The format of this
	output is described below under 'CONFIGURATION FILE'.

  * `--block <ip/range>`: Block (deny, drop) the isolated machine from
    communicating with the indicated IP addresses. These are always at
	a higher priority than `--allow` addresses, regardless of the order
	they are specified. Some useful ranges are the local network (like
	`10.0.0.0/8`) and broadcast/multicast addresses (like 
	`224.0.0.0-255.255.255.255`).

  * `--blockfile <filename>`: Adds all the ranges in the file to the block
    list.  A useful file might be the `default-block.conf` file that comes
    with isowall.

  * `--iflist`: List the available network interfaces, and then exits. This
    is useful to discover which interfaces isowall can see.

  * `--packet-trace`: Prints a summary of packets that are successfully 
    forwarded through isowall, one summary per line.
	This is useful at low rates, like a few packets per second, but will
	overwhelm the terminal at high rates.

  * `--regress`: Run a regression test, returns '0' on success and '1' on
    failure.
    

## CONFIGURATION FILE FORMAT

The configuration file uses the same parameter names as on the
commandline, but without the `--` prefix, and with an `=` sign
between the name and the value. An example configuration file
might be:

	internal = eth1
	internal-target-ip = 10.20.30.207

	reuse-external = true
	external = eth0
	external-router-ip = 10.0.0.1

	allow = 0.0.0.0/0

	block = 10.0.0.0/8
	block = 224.0.0.0-255.255.255.255
	blockfile = default-block.conf


By default, the program will read default configuration from the file
`/etc/isowall.conf`.

## SEE ALSO

pcap(3)

## AUTHORS

This tool was written by Robert Graham. The source code is available at
https://github.com/robertdavidgraham/isowall.
