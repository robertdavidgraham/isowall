#ifndef ISOWALL_H
#define ISOWALL_H
#include "ranges.h"

enum {
    Operation_Default,
    Operation_Bridge,
    Operation_Selftest,
    Operation_List_Adapters,    
    Operation_DebugIF,
};


/**
 * There are two adapters in the system, the "internal" and
 * "external" adapter.
 */
struct Adapter {
    /** The name of the network adapter, such as "eth1" */
    char *ifname;

    /** The MAC address of this adapter. This isn't ever used when
     * transmitting/receiving packets since we are in promiscuous
     * mode bridging other packets. Instead, it's used to verify
     * that no packet contains this MAC address -- the internal
     * network adapters should never be used for normal communications */
    unsigned char my_mac[6];

    /** The target IP address. On the "internal" adapter, this is the
     * target we are isolating. On the "external" adapter, this will
     * be the IP address of the router */
    unsigned target_ip;

    /** The target's MAC address. On the "internal" adapter, this will
     * be the isolated target machine. On the "external" network,
     * this will be the router's IP address. This should be manually
     * configured, but if it isn't, we'll ARP the target IP address
     * to find this MAC address */
    unsigned char target_mac[6];

    /** Any additional "BPF filter" the user wants to configure on
     * an interface. */
    char *bpf_filter;

    struct RawAdapter *raw;

    struct {
        uint64_t allowed;
        uint64_t blocked;
    } stats;
};


/**
 * This is the master configuration structure. This contains everything
 * that was configured on the command-line or within the .conf file.
 */
struct IsoWall {
    unsigned op;

    struct Adapter in;
    struct Adapter ex;

    struct RangeList allow;
    struct RangeList block;

    unsigned char ttl;
    unsigned is_packet_trace:1;
    unsigned is_pfring:1;
    unsigned is_sendq:1;
    unsigned is_offline:1;
    unsigned is_reuse_external:1;
    unsigned is_reuse_internal:1;
};

/**
 * Given a filename, read in the configuration. This is called from three
 * places. It'll be called from the main() function with the filename
 * "/etc/isowall.conf". It may also be called while parsing the command-line
 * if the "-c" or "--conf" parameter is given. Lastly, it can be recursively
 * called with the "conf = <filename>" parameter.
 */
void isowall_read_config_file(struct IsoWall *isowall, const char *filename);

/**
 * Parses the command-line. Called by main().
 */
void isowall_command_line(struct IsoWall *isowall, int argc, char *argv[]);


void isowall_usage();

#endif
