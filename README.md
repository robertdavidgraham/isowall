isowall
=======

This is a mini-firewall that completely isolates a target device from the local network.

# Building

This project depends upon `libpcap`, and of course a C compiler.

On Debian, the following should work:

    # apt-get install git gcc make libpcap-dev
    # git clone https://github.com/robertdavidgraham/isowall
    # cd isowall
    # make
  
This will put the binary `isowall` in the local `isowall/bin` directory.

This should also work on Windows, Mac OS X, xBSD, and pretty much any operating system that supports `libpcap`.


# Running

First of all, make sure that the network interfaces have no IP addresses bound, no any network stack.
This is the most important step: the idea is that we are copmletely isolating the target device
from any local networks. That device should not be able to detect the presence of `isowall` with
anything going across the network.

The typical way of running `isowall` is to plug in two USB Ethernet adapters into a simple device like
a Raspberry Pi, then configuring this software to bridge between them. The original Ethernet adapter built
into the Raspberry Pi is used for normal SSH communication. In other words, the typical configuration
will have three Ethernet adapters: one for control (and a real network stack), and two for running purely
with `libpcap`.

To run, simply type:

    # ./bin/isowall -c xxxx.conf
  
where `xxxx.conf` contains your configuration, which is described


# Configuration

The following shows a typical configuration file

    internal = eth1
    internal.target.ip = 10.0.0.129
    internal.target.mac = 02:60:8c:37:87:f3
  
    external = eth2
    external.router.ip = 10.0.0.1
    external.router.mac = 66:55:44:33:22:11
  
    allow = 0.0.0.0/0
    block = 192.168.0.0/16
    block = 10.0.0.0/8
    block = 224.0.0.0-255.255.255.255


The target device we are isolating has the indicated IP and MAC address.

Only IPv4 and ARP packets are passed.

Outbound packets must have the following conditions:
  * source MAC address equal to `internal.target.mac`
  * destination MAC address equal to `external.router.mac`
  * EtherType of 0x800 or 0x806
  * source IPv4 address equal to `internal.target.ip`
  * destination IPv4 address within an `allow` range, but not in a `block` range
  * if an ARP packet, then the destination IPv4 address must equal that `external.router.ip`
  * if an ARP packet, must be a "request"

Inbound packets must have the following conditions:
  * destination MAC address equal to `internal.target.mac`
  * source MAC address equal to `external.router.mac`
  * EtherType of 0x800 or 0x806
  * destination IPv4 address equal to `internal.target.ip`
  * source IPv4 address within an `allow` range, but not in a `block` range
  * if an ARP packet, then the source IPv4 address must equal that `external.router.ip`
  * if an ARP packet, then must be a "reply"

