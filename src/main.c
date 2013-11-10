#include "isowall.h"
#include "string_s.h"
#include "logger.h"
#include "rawsock.h"
#include "pixie-threads.h"
#include <pcap.h>
#include <string.h>

#if defined(WIN32)
#include <Windows.h>
#else
#include <unistd.h>
#endif


/****************************************************************************
 * @return
 *      1 if the packet is OK
 *      0 if the packet is bad
 ****************************************************************************/
static int
is_valid(const unsigned char *px, size_t length,
    const struct Adapter *src, const struct Adapter *dst,
    const struct RangeList *allowed,
    int is_inbound)
{
    unsigned ethertype;

    /*
     * validate:
     *      Ethernet frames are a minimum of 60 bytes. This also makes sure
     *      there is enough to contain the full IP header or ARP packet
     */
    if (length < 42)
        return 0;

    /*
     * validate:
     *      Etheretype must be IPv4 or ARP
     */
    ethertype = px[12]<<8 | px[13];
    if (ethertype != 0x800 && ethertype != 0x806)
        return 0;

    /*
     * validate:
     *      MAC address of this packet must be only our target and the
     *      router, going in the correct direction
     */
    if (memcmp(px+0, "\xFF\xFF\xFF\xFF\xFF\xFF", 6) == 0 && ethertype == 0x806)
        ; /* ARP packets can be broadcast packets instead */
    else if (memcmp(px+0, dst->target_mac, 6) != 0)
        return 0;
    if (memcmp(px+6, "\x00\x00\x00\x00\x00\x00", 6) == 0)
        ; /* temporary kludge for VMware testing */
    else if (memcmp(px+6, src->target_mac, 6) != 0)
        return 0;

    /*
     * If IPv4, extract addresses and return     
     */
    if (ethertype == 0x800) {
        unsigned src_ip;
        unsigned dst_ip;
        src_ip =      px[14+12+0]<<24
                    | px[14+12+1]<<16
                    | px[14+12+2]<< 8
                    | px[14+12+3]<< 0;
        dst_ip =      px[14+16+0]<<24
                    | px[14+16+1]<<16
                    | px[14+16+2]<< 8
                    | px[14+16+3]<< 0;

        if (is_inbound) {
            if (dst_ip != dst->target_ip)
                return 0;
            if (!rangelist_is_contains(allowed, src_ip))
                return 0;
        } else {
            if (src_ip != src->target_ip)
                return 0;
            if (!rangelist_is_contains(allowed, dst_ip))
                return 0;
        }

        return 1;
    } else if (ethertype == 0x806) {
        struct ARP_Packet {
            unsigned opcode;
            unsigned hardware_type;
            unsigned protocol_type;
            unsigned hardware_length;
            unsigned protocol_length;
            unsigned ip_src;
            unsigned ip_dst;
            const unsigned char *mac_src;
            const unsigned char *mac_dst;
        } arp[1];
        unsigned offset;
    
        /*
         * Parse the basic ARP header
         */
        offset = 14;
        arp->hardware_type = px[offset]<<8 | px[offset+1];
        arp->protocol_type = px[offset+2]<<8 | px[offset+3];
        arp->hardware_length = px[offset+4];
        arp->protocol_length = px[offset+5];
        arp->opcode = px[offset+6]<<8 | px[offset+7];
        offset += 8;

        /* We only support IPv4 and Ethernet addresses */
        if (arp->protocol_length != 4 && arp->hardware_length != 6)
            return 0;
        if (arp->protocol_type != 0x0800)
            return 0;
        if (arp->hardware_type != 1 && arp->hardware_type != 6)
            return 0;

        /*
         * parse the addresses
         */
        arp->mac_src = px+offset;
        offset += arp->hardware_length;

        arp->ip_src = px[offset+0]<<24 | px[offset+1]<<16 | px[offset+2]<<8 | px[offset+3];
        offset += arp->protocol_length;

        arp->mac_dst = px+offset;
        offset += arp->hardware_length;

        arp->ip_dst = px[offset+0]<<24 | px[offset+1]<<16 | px[offset+2]<<8 | px[offset+3];
        offset += arp->protocol_length;

        /* validate:
         *      Validate that source/destination are correct
         */
        if (arp->ip_src != src->target_ip)
            return 0;
        if (memcmp(arp->mac_src, src->target_mac, 6) != 0)
            return 0;
        if (arp->ip_dst != dst->target_ip)
            return 0;

        /*
         * Validate depending on opcode
         */
        switch (arp->opcode) {
        case 1: /* request */
            /* no further validation needs to be done */
            break;
        case 2: /* reply */
            /* validate:
             *      make sure the destination MAC address is correct */
            if (memcmp(arp->mac_dst, dst->target_mac, 6) != 0)
                return 0;
            /* validate:
             *      make sure this isn't a broadcast packet; we allowed it above
             *      but in this case, it shouldn't be valid
             */
            if (memcmp(px+0, "\xFF\xFF\xFF\xFF\xFF\xFF", 6) == 0)
                return 0;
            break;
        default:
            return 0;
        }

        return 1;
    } else
        return 0;
}

/****************************************************************************
 ****************************************************************************/
static int
is_myself(const unsigned char *mac, const unsigned char *px, unsigned length)
{
    if (length < 12)
        return 0;
    if (memcmp(px+0, mac, 6) == 0)
        return 1;
    if (memcmp(px+6, mac, 6) == 0)
        return 1;
    return 0;
}

/****************************************************************************
 ****************************************************************************/
void
inbound_thread(void *v)
{
    struct IsoWall *isowall = (struct IsoWall *)v;
    struct Adapter *src = &isowall->ex;
    struct Adapter *dst = &isowall->in;
    const struct RangeList *allowed = &isowall->allow;

    for (;;) {
        const unsigned char *px;
        unsigned length;
        int err;
        unsigned secs;
        unsigned usecs;

        /*
         * Receive a packet from the network
         */
        err = rawsock_recv_packet(
                    src->raw,
                    &length,
                    &secs,
                    &usecs,
                    &px);
        if (err != 0 || length == 0)
            continue;

        if (!isowall->is_reuse_external && is_myself(src->my_mac, px, length)) {
            LOG(0, "*** DANGER *** DANGER *** DANGER ***\n");
            LOG(0, " A packet was discovered with MAC address of the adapter, \n");
            LOG(0, " indicating that some other software has started using this \n");
            LOG(0, " network. You are now exposed to the infected machine. Isowall \n");
            LOG(0, " is shutting down\n");
            LOG(0, "*** DANGER *** DANGER *** DANGER ***\n");
            exit(1);
        }

        if (is_valid(px, length, src, dst, allowed, 1)) {
            src->stats.allowed++;
            rawsock_send_packet(dst->raw, px, length, 1);
        } else
            src->stats.blocked++;

    }
}

/****************************************************************************
 * Same as inbound thread, but src/dst reversed, and is_inbound parameter
 * reversed. I need to make these two the same function.
 ****************************************************************************/
void
outbound_thread(void *v)
{
    struct IsoWall *isowall = (struct IsoWall *)v;
    struct Adapter *src = &isowall->in;
    struct Adapter *dst = &isowall->ex;
    const struct RangeList *allowed = &isowall->allow;

    for (;;) {
        const unsigned char *px;
        unsigned length;
        int err;
        unsigned secs;
        unsigned usecs;

        /*
         * Receive a packet from the network
         */
        err = rawsock_recv_packet(
                    src->raw,
                    &length,
                    &secs,
                    &usecs,
                    &px);
        if (err != 0 || length == 0)
            continue;

        if (!isowall->is_reuse_internal && is_myself(src->my_mac, px, length)) {
            LOG(0, "*** DANGER *** DANGER *** DANGER ***\n");
            LOG(0, " A packet was discovered with MAC address of the adapter, \n");
            LOG(0, " indicating that some other software has started using this \n");
            LOG(0, " network. You are now exposed to the infected machine. Isowall \n");
            LOG(0, " is shutting down\n");
            LOG(0, "*** DANGER *** DANGER *** DANGER ***\n");
            exit(1);
        }

        if (is_valid(px, length, src, dst, allowed, 0)) {
            src->stats.allowed++;
            rawsock_send_packet(dst->raw, px, length, 1);
        } else
            src->stats.blocked++;

    }
}

/****************************************************************************
 ****************************************************************************/
static void
isowall_bridge(struct IsoWall *isowall)
{
    unsigned x;
    struct RawAdapter *raw;
    unsigned char *mac;

    /*
     * Combine the "white-list" and "blacklist" into a single set
     * of "whitelist" ranges.
     */
    rangelist_exclude(&isowall->allow, &isowall->block);
    if (rangelist_count(&isowall->allow) == 0) {
        LOG(0, "FAIL: everything is blocked\n");
        LOG(0, "...hint: do something like '--allow 0.0.0.0/0'\n");
        LOG(0, "...hint: don't do something like '--block 0.0.0.0/0'\n");
        exit(1);
    }

    /*
     * Make sure the user has specified both network adapters
     */
    if (isowall->in.ifname == NULL || isowall->in.ifname[0] == '\0') {
        if (!isowall->is_reuse_internal) {
            LOG(0, "FAIL: no internal network adapter specified\n");
            LOG(0, "...hint: do something like '--internal eth1'\n");
            LOG(0, "...info: internal network is the isolated side\n");
            exit(1);
        }
    }
    if (isowall->ex.ifname == NULL || isowall->ex.ifname[0] == '\0') {
        if (isowall->is_reuse_external) {
            /* no adapter specified, so find a default one */
            int err;
            char ifname2[256];
            size_t len;
		    ifname2[0] = '\0';
            err = rawsock_get_default_interface(ifname2, sizeof(ifname2));
            if (err || ifname2[0] == '\0') {
                fprintf(stderr, "FAIL: could not determine default external interface\n");
                fprintf(stderr, "...hint: try something like \"--external eth2\"\n");
                exit(1);
            } else {
                LOG(0, "external-ifname = %s\n", ifname2);
            }
            len = strlen(ifname2) + 1;
            isowall->ex.ifname = (char*)malloc(len);
            if (isowall->ex.ifname)
                strcpy_s(isowall->ex.ifname, len, ifname2);
        } else {
            LOG(0, "FAIL: no external network adapter specified\n");
            LOG(0, "...hint: do something like '--external eth2'\n");
            LOG(0, "...info: external network is the side exposed to Internet\n");
            exit(1);
        }
    }

    /*
     * Make sure we know the IP addresses of the internal target and the
     * external router
     */
    if (isowall->in.target_ip == 0) {
        LOG(0, "FAIL: the IP address of the internal isolated machine not specified\n");
        LOG(0, "...hint: do something like '--internal-target-ip 10.0.0.137'\n");
        exit(1);
    }
    if (isowall->ex.target_ip == 0) {
        if (isowall->is_reuse_external) {
            int err;
            unsigned ip;

            err = rawsock_get_default_gateway(  isowall->ex.ifname, 
                                                &ip);
            if (err || ip == 0) {
                LOG(0, "FAIL: could not discover external router\n");
                LOG(0, "...hint: do something like '--external-router-ip 10.0.0.137'\n");
                exit(1);
            } else {
                LOG(0, "external-router-ip = %u.%u.%u.%u\n",
                    (unsigned char)(ip>>24),
                    (unsigned char)(ip>>16),
                    (unsigned char)(ip>> 8),
                    (unsigned char)(ip>> 0)
                    );
                isowall->ex.target_ip = ip;
            }
        } else {
            LOG(0, "FAIL: the IP address of the external router not specified\n");
            LOG(0, "...hint: do something like '--external-router-ip 10.0.0.137'\n");
            exit(1);
        }
    }





    /*
     * Make sure we don't have a network stack bound to the adapters
     */
    x = rawsock_get_adapter_ip(isowall->in.ifname);
    if (x != 0 && !isowall->is_reuse_internal) {
        LOG(0, "FAIL: there is an IP address bound to the adapter\n");
        LOG(0, "FAIL: '%s' has IPv4 address %u.%u.%u.%u\n",
            isowall->in.ifname,
            (unsigned char)(x>>24),
            (unsigned char)(x>>16),
            (unsigned char)(x>> 8),
            (unsigned char)(x>> 0)
            );
        LOG(0, "...hint: THIS IS THE MOST IMPORTANT THING TO FULLY UNDERSTAND ABOUT THIS PROGRAM\n");
        exit(1);
    }
    if (!isowall->is_reuse_external) {
        x = rawsock_get_adapter_ip(isowall->ex.ifname);
        if (x != 0) {
            LOG(0, "FAIL: there is an IP address bound to the adapter\n");
            LOG(0, "FAIL: '%s' has IPv4 address %u.%u.%u.%u\n",
                isowall->in.ifname,
                (unsigned char)(x>>24),
                (unsigned char)(x>>16),
                (unsigned char)(x>> 8),
                (unsigned char)(x>> 0)
                );
            LOG(0, "...hint: THIS IS THE MOST IMPORTANT THING TO FULLY UNDERSTAND ABOUT THIS PROGRAM\n");
            exit(1);
        }
    }

    /*
     * Make sure we know the MAC address of the adapters
     */
    mac = isowall->in.my_mac;
    if (memcmp(mac, "\0\0\0\0\0\0", 6) == 0) {
        rawsock_get_adapter_mac(isowall->in.ifname, mac);
        LOG(2, "auto-detected: adapter-mac=%02x-%02x-%02x-%02x-%02x-%02x\n",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
            );
    }
    if (memcmp(mac, "\0\0\0\0\0\0", 6) == 0) {
        fprintf(stderr, "FAIL: failed to detect MAC address of interface: \"%s\"\n", isowall->in.ifname);
        fprintf(stderr, "...hint: try something like \"--internal-my-mac 00-11-22-33-44-55\"\n");
        exit(1);
    }
    mac = isowall->ex.my_mac;
    if (memcmp(mac, "\0\0\0\0\0\0", 6) == 0) {
        rawsock_get_adapter_mac(isowall->ex.ifname, mac);
        LOG(2, "auto-detected: adapter-mac=%02x-%02x-%02x-%02x-%02x-%02x\n",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
            );
    }
    if (memcmp(mac, "\0\0\0\0\0\0", 6) == 0 && !isowall->is_reuse_external) {
        fprintf(stderr, "FAIL: failed to detect MAC address of interface: \"%s\"\n", isowall->in.ifname);
        fprintf(stderr, "...hint: try something like \"--external-my-mac 00-11-22-33-44-55\"\n");
        exit(1);
    }


    /*
     * Open the adapters
     */
    raw = rawsock_init_adapter( isowall->in.ifname,
                                isowall->is_pfring,
                                isowall->is_sendq,
                                isowall->is_packet_trace,
                                isowall->is_offline,
                                isowall->in.bpf_filter);
    if (raw == 0) {
        LOG(0, "FAIL: could not open internal adapter: %s\n", isowall->in.ifname);
        exit(1);
    }
    isowall->in.raw = raw;

    raw = rawsock_init_adapter( isowall->ex.ifname,
                                isowall->is_pfring,
                                isowall->is_sendq,
                                isowall->is_packet_trace,
                                isowall->is_offline,
                                isowall->in.bpf_filter);
    if (raw == 0) {
        LOG(0, "FAIL: could not open internal adapter: %s\n", isowall->ex.ifname);
        exit(1);
    }
    isowall->ex.raw = raw;

    /*
     * If we have to, ARP the target IP addresses
     */
    mac = isowall->in.target_mac;
    if (memcmp(mac, "\0\0\0\0\0\0", 6) == 0) {
        
        LOG(1, "rawsock: looking for target MAC address\n");

        arp_resolve_sync(
                isowall->in.raw,
                isowall->ex.target_ip,  /* spoof the address of other side */
                isowall->ex.target_mac,
                isowall->in.target_ip,
                mac);

        if (memcmp(mac, "\0\0\0\0\0\0", 6) != 0) {
            LOG(0, "internal-target-mac = %02x-%02x-%02x-%02x-%02x-%02x\n",
                mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        } else {
            LOG(0, "FAIL: couldn't find target MAC address\n");
            LOG(0, "...hint: there is probably a networking error\n");
            LOG(0, "...hint: you can manually config with '--internal-target-mac 66:55:44:33:22:11'\n");
        }
    }
    mac = isowall->ex.target_mac;
    if (memcmp(mac, "\0\0\0\0\0\0", 6) == 0) {
        
        LOG(1, "rawsock: looking for default gateway\n");

        arp_resolve_sync(
                isowall->ex.raw,
                isowall->in.target_ip,  /* spoof the address of other side */
                isowall->in.target_mac,
                isowall->ex.target_ip,
                mac);

        if (memcmp(mac, "\0\0\0\0\0\0", 6) != 0) {
            LOG(0, "external-router-mac = %02x-%02x-%02x-%02x-%02x-%02x\n",
                mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        } else {
            LOG(0, "FAIL: couldn't find target MAC address\n");
            LOG(0, "...hint: there is probably a networking error\n");
            LOG(0, "...hint: you can manually config with '--external-router-mac 66:55:44:33:22:11'\n");
        }
    }

    pixie_begin_thread(inbound_thread, 0, isowall);
    pixie_begin_thread(outbound_thread, 0, isowall);

    /* Print continuous status messages */
    for (;;) {
#if defined(WIN32)
        Sleep(1000);
#else
        sleep(1);
#endif

        fprintf(stderr, "inbound[drop=%-8lluforward=%-8llu] outbound[drop=%-8uforward=%-8llu]\r",
                isowall->ex.stats.blocked,
                isowall->ex.stats.allowed,
                isowall->in.stats.blocked,
                isowall->in.stats.allowed); 

    }
    

}

/****************************************************************************
 ****************************************************************************/
int main(int argc, char *argv[])
{
    struct IsoWall isowall[1];

    memset(isowall, 0, sizeof(*isowall));
    
    /*
     * On non-Windows systems, there might be a configuration
     * file in the well-known "/etc" location
     */
#if !defined(WIN32)
    if (access("/etc/isowall.conf", 0) == 0) {
        isowall_read_config_file(isowall, "/etc/isowall.conf");
    }
#endif

    /*
     * Read in the configuration from the command-line.
     */
    isowall_command_line(isowall, argc, argv);
    
    /*
     * Once we've read in the configuration, do the operation that was
     * specified
     */
    switch (isowall->op) {
    case Operation_Default:
    case Operation_Bridge:
        /*
         * THIS IS THE NORMAL THING
         */
        isowall_bridge(isowall);
        return 0;

    case Operation_List_Adapters:
        /* List the network adapters we might want to use for scanning */
        rawsock_list_adapters();
        break;

    case Operation_DebugIF:
        printf("== INTERNAL ==\n");
        rawsock_selftest_if(isowall->in.ifname, isowall->is_reuse_internal);
        printf("\n== EXTERNAL ==\n");
        rawsock_selftest_if(isowall->ex.ifname, isowall->is_reuse_external);
        return 0;

    case Operation_Selftest:
        /*
         * Do a regression test of all the significant units
         */
        {
            int x = 0;
            x += rawsock_selftest();
            x += ranges_selftest();


            if (x != 0) {
                /* one of the selftests failed, so return error */
                fprintf(stderr, "regression test: failed :( \n");
                return 1;
            } else {
                fprintf(stderr, "regression test: success!\n");
                return 0;
            }
        }
        break;
    }


    return 0;
}
