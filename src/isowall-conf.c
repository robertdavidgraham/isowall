/*
    Read in the configuration

    Configuration parameters can be read either from the command-line
    or a configuration file. Long parameters of the --xxxx variety have
    the same name in both.

*/
#include "isowall.h"
#include "ranges.h"
#include "string_s.h"
#include "logger.h"

#include <ctype.h>
#include <limits.h>

/*****************************************************************************
 * Put all exits in one location so that I can set a breakpoint here in
 * the debugger.
 *****************************************************************************/
static void
my_exit(int x)
{
    exit(x);
}

/*****************************************************************************
 *****************************************************************************/
static void
isowall_help(void)
{
    printf("");
    my_exit(1);
}

/****************************************************************************
 ****************************************************************************/
void
isowall_usage(void)
{
    LOG(0, "usage:\n see https://github.com/robertdavidgraham/isowall\n");
    my_exit(1);
}


/****************************************************************************
 ****************************************************************************/
static unsigned
count_cidr_bits(struct Range range)
{
    unsigned i;

    for (i=0; i<32; i++) {
        unsigned mask = 0xFFFFFFFF >> i;

        if ((range.begin & ~mask) == (range.end & ~mask)) {
            if ((range.begin & mask) == 0 && (range.end & mask) == mask)
                return i;
        }
    }

    return 0;
}


/****************************************************************************
 * Echoes the configuration for each network interface
 ****************************************************************************/
static void
echo_nics(const struct IsoWall *isowall, FILE *fp)
{
    const struct Adapter *adapter;
    
    adapter = &isowall->in;

    fprintf(fp, "internal.ifname = %s\n", adapter->ifname?adapter->ifname:"");
    if (adapter->target_ip != 0)
    fprintf(fp, "internal.target.ip = %u.%u.%u.%u\n",
            (adapter->target_ip>>24)&0xFF,
            (adapter->target_ip>>16)&0xFF,
            (adapter->target_ip>> 8)&0xFF,
            (adapter->target_ip>> 0)&0xFF
            );
    if (memcmp(adapter->target_mac, "\0\0\0\0\0\0", 6) != 0)
    fprintf(fp, "internal.target.mac = %02x:%02x:%02x:%02x:%02x:%02x\n",
            adapter->target_mac[0],
            adapter->target_mac[1],
            adapter->target_mac[2],
            adapter->target_mac[3],
            adapter->target_mac[4],
            adapter->target_mac[5]);
    if (memcmp(adapter->my_mac, "\0\0\0\0\0\0", 6) != 0)
    fprintf(fp, "internal.my.mac = %02x:%02x:%02x:%02x:%02x:%02x\n",
            adapter->my_mac[0],
            adapter->my_mac[1],
            adapter->my_mac[2],
            adapter->my_mac[3],
            adapter->my_mac[4],
            adapter->my_mac[5]);


    adapter = &isowall->ex;

    fprintf(fp, "external.ifname = %s\n", adapter->ifname?adapter->ifname:"");
    if (adapter->target_ip != 0)
    fprintf(fp, "external.router.ip = %u.%u.%u.%u\n",
            (adapter->target_ip>>24)&0xFF,
            (adapter->target_ip>>16)&0xFF,
            (adapter->target_ip>> 8)&0xFF,
            (adapter->target_ip>> 0)&0xFF
            );
    if (memcmp(adapter->target_mac, "\0\0\0\0\0\0", 6) != 0)
    fprintf(fp, "external.router.mac = %02x:%02x:%02x:%02x:%02x:%02x\n",
            adapter->target_mac[0],
            adapter->target_mac[1],
            adapter->target_mac[2],
            adapter->target_mac[3],
            adapter->target_mac[4],
            adapter->target_mac[5]);
    if (memcmp(adapter->my_mac, "\0\0\0\0\0\0", 6) != 0)
    fprintf(fp, "external.my.mac = %02x:%02x:%02x:%02x:%02x:%02x\n",
            adapter->my_mac[0],
            adapter->my_mac[1],
            adapter->my_mac[2],
            adapter->my_mac[3],
            adapter->my_mac[4],
            adapter->my_mac[5]);


}

/****************************************************************************
 ****************************************************************************/
static void
echo_ranges(const struct RangeList *ranges, FILE *fp, const char *name)
{
    unsigned i;

    for (i=0; i<ranges->count; i++) {
        struct Range range = ranges->list[i];
        fprintf(fp, "%s = ", name);
        fprintf(fp, "%u.%u.%u.%u",
            (range.begin>>24)&0xFF,
            (range.begin>>16)&0xFF,
            (range.begin>> 8)&0xFF,
            (range.begin>> 0)&0xFF
            );
        if (range.begin != range.end) {
            unsigned cidr_bits = count_cidr_bits(range);

            if (cidr_bits) {
                fprintf(fp, "/%u", cidr_bits);
            } else {
                fprintf(fp, "-%u.%u.%u.%u",
                    (range.end>>24)&0xFF,
                    (range.end>>16)&0xFF,
                    (range.end>> 8)&0xFF,
                    (range.end>> 0)&0xFF
                    );
            }
        }
        fprintf(fp, "\n");
    }
}

/****************************************************************************
 ****************************************************************************/
static void
isowall_echo(const struct IsoWall *isowall, FILE *fp)
{
    echo_nics(isowall, fp);

    fprintf(fp, "\n");

    echo_ranges(&isowall->allow, fp, "allow");
    echo_ranges(&isowall->block, fp, "block");
}


/*****************************************************************************
 * Read in ranges from a file
 *
 * There can be multiple ranges on a line, delimited by spaces. In fact,
 * millions of ranges can be on a line: there is limit to the line length.
 * That makes reading the file a little bit squirrelly. From one perspective
 * this parser doesn't treat the the new-line '\n' any different than other
 * space. But, from another perspective, it has to, because things like
 * comments are terminated by a newline. Also, it has to count the number
 * of lines correctly to print error messages.
 *****************************************************************************/
static void
ranges_from_file(struct RangeList *ranges, const char *filename)
{
    FILE *fp;
    errno_t err;
    unsigned line_number = 0;


    err = fopen_s(&fp, filename, "rt");
    if (err) {
        perror(filename);
        my_exit(1); /* HARD EXIT: because if it's an exclusion file, we don't
                  * want to continue. We don't want ANY chance of
                  * accidentally scanning somebody */
    }

    while (!feof(fp)) {
        int c = '\n';

        /* remove leading whitespace */
        while (!feof(fp)) {
            c = getc(fp);
            line_number += (c == '\n');
            if (!isspace(c&0xFF))
                break;
        }

        /* If this is a punctuation, like '#', then it's a comment */
        if (ispunct(c&0xFF)) {
            while (!feof(fp)) {
                c = getc(fp);
                line_number += (c == '\n');
                if (c == '\n') {
                    break;
                }
            }
            /* Loop back to the begining state at the start of a line */
            continue;
        }

        if (c == '\n') {
            continue;
        }

        /*
         * Read in a single entry
         */
        if (!feof(fp)) {
            char address[64];
            size_t i;
            struct Range range;
            unsigned offset = 0;


            /* Grab all bytes until the next space or comma */
            address[0] = (char)c;
            i = 1;
            while (!feof(fp)) {
                c = getc(fp);
                line_number += (c == '\n');
                if (isspace(c&0xFF) || c == ',') {
                    break;
                }
                if (i+1 >= sizeof(address)) {
                    LOG(0, "%s:%u:%u: bad address spec: \"%.*s\"\n",
                            filename, line_number, offset, i, address);
                    my_exit(1);
                } else
                    address[i] = (char)c;
                i++;
            }
            address[i] = '\0';

            /* parse the address range */
            range = range_parse_ipv4(address, &offset, (unsigned)i);
            if (range.begin == 0xFFFFFFFF && range.end == 0) {
                LOG(0, "%s:%u:%u: bad range spec: \"%.*s\"\n", 
                        filename, line_number, offset, i, address);
                my_exit(1);
            } else {
                rangelist_add_range(ranges, range.begin, range.end);
            }
        }

    }

    fclose(fp);
}

/***************************************************************************
 ***************************************************************************/
static unsigned
hexval(char c)
{
    if ('0' <= c && c <= '9')
        return (unsigned)(c - '0');
    if ('a' <= c && c <= 'f')
        return (unsigned)(c - 'a' + 10);
    if ('A' <= c && c <= 'F')
        return (unsigned)(c - 'A' + 10);
    return 0xFF;
}

/***************************************************************************
 ***************************************************************************/
static int
parse_mac_address(const char *text, unsigned char *mac)
{
    unsigned i;

    for (i=0; i<6; i++) {
        unsigned x;
        char c;

        while (isspace(*text & 0xFF) && ispunct(*text & 0xFF))
            text++;

        c = *text;
        if (!isxdigit(c&0xFF))
            return -1;
        x = hexval(c)<<4;
        text++;

        c = *text;
        if (!isxdigit(c&0xFF))
            return -1;
        x |= hexval(c);
        text++;

        mac[i] = (unsigned char)x;

        if (ispunct(*text & 0xFF))
            text++;
    }

    return 0;
}




/***************************************************************************
 * Tests if the named parameter on the command-line. We do a little
 * more than a straight string compare, because I get confused 
 * whether parameter have punctuation. Is it "--excludefile" or
 * "--exclude-file"? I don't know if it's got that dash. Screw it,
 * I'll just make the code so it don't care.
 ***************************************************************************/
static int
EQUALS(const char *lhs, const char *rhs)
{
    for (;;) {
        while (*lhs == '-' || *lhs == '.' || *lhs == '_')
            lhs++;
        while (*rhs == '-' || *rhs == '.' || *rhs == '_')
            rhs++;
        if (*lhs == '\0' && *rhs == '[')
            return 1; /*arrays*/
        if (tolower(*lhs & 0xFF) != tolower(*rhs & 0xFF))
            return 0;
        if (*lhs == '\0')
            return 1;
        lhs++;
        rhs++;
    }
}

/***************************************************************************
 ***************************************************************************/
static void
adapter_set_parameter(struct Adapter *adapter,
                      const char *name, const char *value)
{
    if (EQUALS("name", name) || EQUALS("ifname", name) || name[0] == '\0') {
        /*
         * The 'name' of the adapter, like "eth1"
         */
        size_t len = strlen(value) + 1;
        if (adapter->ifname != 0 && adapter->ifname[0] != 0) {
            LOG(0, "WARNING: overwriting adapter name, from '%s' to '%s'\n",
                adapter->ifname, value);
        }
        if (adapter->ifname)
            free(adapter->ifname);
        adapter->ifname = (char*)malloc(len);
        if (adapter->ifname)
            strcpy_s(adapter->ifname, len, value);
    } else if (EQUALS("target-ip", name) || EQUALS("ip", name) 
                || EQUALS("router-ip", name)) {
        struct Range range;

        range = range_parse_ipv4(value, 0, 0);

        /* Check for bad format */
        if (range.begin != range.end) {
            LOG(0, "FAIL: bad IPv4 address: %s=%s\n", 
                    name, value);
            LOG(0, "hint   addresses look like \"19.168.1.23\"\n");
            my_exit(1);
        }

        adapter->target_ip = range.begin;
    } else if (EQUALS("target-mac", name) || EQUALS("router-mac", name)) {
        unsigned char mac[6];

        if (parse_mac_address(value, mac) != 0) {
            fprintf(stderr, "FAIL: bad MAC address: %s=%s\n", name, value);
            my_exit(1);
            return;
        }

        memcpy(adapter->target_mac, mac, 6);
    } else if (EQUALS("my-mac", name) || EQUALS("me", name)) {
        unsigned char mac[6];

        if (parse_mac_address(value, mac) != 0) {
            fprintf(stderr, "FAIL: bad MAC address: %s=%s\n", name, value);
            my_exit(1);
            return;
        }

        memcpy(adapter->my_mac, mac, 6);
    } else if (EQUALS("bpf", name)) {
        size_t len = strlen(value) + 1;
        if (adapter->bpf_filter) {
            LOG(0, "WARNING: overwriting BPF filter\n");
            free(adapter->bpf_filter);
        }
        adapter->bpf_filter = (char*)malloc(len);
        if (adapter->bpf_filter)
            memcpy(adapter->bpf_filter, value, len);
    } else {
        LOG(0, "unknown adapter configuration parameter: %s=%s\n", 
            name, value);
        my_exit(1);
    }
}

/***************************************************************************
 ***************************************************************************/
static void
parse_ranges(struct RangeList *list, const char *value)
{
    unsigned offset = 0;
    unsigned max_offset = (unsigned)strlen(value);

    /* multiple ranges can be specified on a line */
    for (;;) {
        struct Range range;

        /* parse the range */
        range = range_parse_ipv4(value, &offset, max_offset);
        if (range.end < range.begin) {
            fprintf(stderr, "FAIL: bad IP address/range: %s\n", value);
            my_exit(1);
        }

        /* add to our allow/block list */
        rangelist_add_range(list, range.begin, range.end);

        if (offset >= max_offset || value[offset] != ',')
            break;
        else
            offset++; /* skip comma */
    }
}

/***************************************************************************
 * Called either from the "command-line" parser when it sees a --parm,
 * or from the "config-file" parser for normal options.
 ***************************************************************************/
static int
isowall_set_parameter(struct IsoWall *isowall, 
                      const char *name, const char *value)
{
    if (memcmp("in", name, 2) == 0) {
        while (*name && *name != '.' && *name != '-')
            name++;
        while (ispunct(name[0]&0xFF))
            name++;
        adapter_set_parameter(&isowall->in, name, value);
    } else if (memcmp("ex", name, 2) == 0) {
        while (*name && *name != '.' && *name != '-')
            name++;
        while (ispunct(name[0]&0xFF))
            name++;
        adapter_set_parameter(&isowall->ex, name, value);
    } else if (EQUALS("conf", name) || EQUALS("config", name)) {
        isowall_read_config_file(isowall, value);
    } else if (EQUALS("allow", name) || EQUALS("whitelist", name)
                || EQUALS("accept", name)) {
        parse_ranges(&isowall->allow, value);
    } else if (EQUALS("block", name) || EQUALS("blacklist", name)
                || EQUALS("deny", name) || EQUALS("drop", name)) {
        parse_ranges(&isowall->block, value);
    } else if (EQUALS("debug", name)) {
        if (EQUALS("if", value)) {
            isowall->op = Operation_DebugIF;
        } else {
            LOG(0, "unknown debug function: %s\n", value);
            my_exit(1);
        }
    } else if (EQUALS("echo", name)) {
        isowall_echo(isowall, stdout);
        my_exit(1);
    } else if (EQUALS("help", name)) {
        isowall_help();
        my_exit(1);
    } else if (EQUALS("excludefile", name) || EQUALS("blockfile", name)
                || EQUALS("denyfile", name) || EQUALS("dropfile", name)) {
        unsigned count1 = isowall->block.count;
        unsigned count2;
        ranges_from_file(&isowall->block, value);
        count2 = isowall->block.count;
        if (count2 - count1)
            LOG(1, "%s: adding %u BLOCK ranges from file\n", 
                    value, count2 - count1);
    } else if (EQUALS("includefile", name) || EQUALS("allowfile", name)
                || EQUALS("acceptfile", name) || EQUALS("passfile", name)) {
        unsigned count1 = isowall->block.count;
        unsigned count2;
        ranges_from_file(&isowall->block, value);
        count2 = isowall->block.count;
        if (count2 - count1)
            LOG(1, "%s: adding %u ALLOW ranges from file\n", 
                    value, count2 - count1);
    } else if (EQUALS("iflist", name) || EQUALS("listif", name)) {
        isowall->op = Operation_List_Adapters;
        return 0;
    } else if (EQUALS("packet-trace", name) || EQUALS("trace-packet", name)) {
        isowall->is_packet_trace = 1;
        return 0;
    } else if (EQUALS("pfring", name)) {
        isowall->is_pfring = 1;
        return 0;
    } else if (EQUALS("reuse", name) || EQUALS("reuse-external", name)) {
        isowall->is_reuse_external = 1;
        return 0;
    } else if (EQUALS("reuse-external", name)) {
        isowall->is_reuse_internal = 1;
        return 0;
    } else if (EQUALS("sendq", name)) {
        isowall->is_sendq = 1;
        return 0;
    } else if (EQUALS("selftest", name) || EQUALS("self-test", name) || EQUALS("regress", name)) {
        isowall->op = Operation_Selftest;
        return 0;
    } else if (EQUALS("ttl", name)) {
        unsigned x = strtoul(value, 0, 0);
        if (x >= 256) {
            fprintf(stderr, "error: %s=<n>: expected number less than 256\n", name);
        } else {
            isowall->ttl = x;
        }
    } else {
        fprintf(stderr, "FAIL: unknown config option: %s=%s\n", name, value);
        my_exit(1);
    }
    return 1;
}



/***************************************************************************
 * Read the configuration from the command-line.
 * Called by 'main()' when starting up.
 ***************************************************************************/
void
isowall_command_line(struct IsoWall *isowall, int argc, char *argv[])
{
    int i;

    for (i=1; i<argc; i++) {

        /*
         * --name=value
         * --name:value
         * -- name value
         */
        if (argv[i][0] == '-' && argv[i][1] == '-') {
            char name2[64];
            char *name = argv[i] + 2;
            unsigned name_length;
            const char *value;
            int increment = 0;

            value = strchr(&argv[i][2], '=');
            if (value == NULL)
                value = strchr(&argv[i][2], ':');
            if (value == NULL) {
                if (i+1 < argc)
                    value = argv[i+1];
                else
                    value = "";
                name_length = (unsigned)strlen(name);
            } else {
                name_length = (unsigned)(value - name);
                value++;
            }


            if (name_length > sizeof(name2) - 1) {
                fprintf(stderr, "%.*s: name too long\n", name_length, name);
                name_length = sizeof(name2) - 1;
            }

            memcpy(name2, name, name_length);
            name2[name_length] = '\0';

            increment = isowall_set_parameter(isowall, name2, value);

            i += increment;

            if (i >= argc) {
                fprintf(stderr, "%.*s: empty parameter\n", name_length, name);
                break;
            }
            continue;
        }

        /* For for a single-dash parameter */
        if (argv[i][0] == '-') {
            const char *arg;

            switch (argv[i][1]) {
            case 'c':
                if (argv[i][2])
                    arg = argv[i]+2;
                else
                    arg = argv[++i];
                isowall_read_config_file(isowall, arg);
                break;
            case 'd': /* just do same as verbosity level */
                {
                    int v;
                    for (v=1; argv[i][v] == 'd'; v++) {
                        LOG_add_level(1);
					}
                }
                break;
            case 'h':
            case '?':
                isowall_usage();
                break;
            case 'v':
                {
                    int v;
                    for (v=1; argv[i][v] == 'v'; v++)
                        LOG_add_level(1);
                }
                break;
            case 'W':
                isowall->op = Operation_List_Adapters;
                return;
            default:
                LOG(0, "FAIL: unknown option: -%s\n", argv[i]);
                LOG(0, " [hint] try \"--help\"\n");
                my_exit(1);
            }
            continue;
        }

        fprintf(stderr, "FAIL: unknown command-line parameter \"%s\"\n", argv[i]);
        fprintf(stderr, " [hint] did you want \"--%s\"?\n", argv[i]);
        my_exit(1);
    }
}

/***************************************************************************
 * remove leading/trailing whitespace
 ***************************************************************************/
static void
trim(char *line, size_t sizeof_line)
{
    if (sizeof_line > strlen(line))
        sizeof_line = strlen(line);
    
    while (isspace(*line & 0xFF))
        memmove(line, line+1, sizeof_line--);
    while (isspace(line[sizeof_line-1] & 0xFF))
        line[--sizeof_line] = '\0';
}

/***************************************************************************
 ***************************************************************************/
void
isowall_read_config_file(struct IsoWall *isowall, const char *filename)
{
    FILE *fp;
    errno_t err;
    char line[65536];

    err = fopen_s(&fp, filename, "rt");
    if (err) {
        perror(filename);
        return;
    }

    while (fgets(line, sizeof(line), fp)) {
        char *name;
        char *value;

        trim(line, sizeof(line));

        if (ispunct(line[0] & 0xFF) || line[0] == '\0')
            continue;

        name = line;
        value = strchr(line, '=');
        if (value == NULL)
            continue;
        *value = '\0';
        value++;
        trim(name, sizeof(line));
        trim(value, sizeof(line));

        isowall_set_parameter(isowall, name, value);
    }

    fclose(fp);
}


/***************************************************************************
 ***************************************************************************/
int
mainconf_selftest()
{
    char test[] = " test 1 ";
    
    trim(test, sizeof(test));
    if (strcmp(test, "test 1") != 0)
        return 1; /* failure */
 
    {
        struct Range range;
        
        range.begin = 16;
        range.end = 32-1;
        if (count_cidr_bits(range) != 28)
            return 1;

        range.begin = 1;
        range.end = 13;
        if (count_cidr_bits(range) != 0)
            return 1;


    }

    return 0;
}
