isowall
=======

This is a mini-firewall that completely isolates a target device from the local network.
This is for allowing infected machines Internet access, but without endangering the
local network.


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

First, setup a machine with three network interfaces.

The first network interface (like `eth0`) will be configured as normal, with a TCP/IP stack,
so that you can SSH to it.

The other two network interfaces should have no TCP/IP stack, no IP address, no anything. This is the
most important configuration step, and the most common thing you'll get wrong. For examlpe, the DHCP
software on the box may be confgiured to automatically send out DHCP requests on these additional
interfaces. You have to go fix that so nothing is bound to these interfaces.

To run, simply type:

    # ./bin/isowall --internal eth1 --external eth2 -c xxxx.conf
  
where `xxxx.conf` contains your configuration, which is described below.


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


# Security Guarantee

There is no guarantee, of course, but this program has pretty good security.

The security rests on the fact that there is **no IP stack bound to adapters**.
What that means is that the infected targetted cannot touch the firewall
machine in any way, except as allowed within the `is_allowed()` function.
That function represents the majority of the attack surface for the firewall
machine. And, as you can tell from reading the function, it contains almost
no functionality, meaning that the attack surface is very small indeed.

There are a few theoretical attacks that might happen at the physical layer,
but for the most part, we don't have to worry about them.




