#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <getopt.h>
#include <cstring>
#include <arpa/inet.h>
#include <limits.h>

#define DEVICE_INTF_NAME "mfw_simulated.txt"

struct mfw_rule {
    int in;                     // 1 = in, 0 = out
    uint32_t s_ip;
    uint32_t s_mask;
    uint16_t s_port;
    uint32_t d_ip;
    uint32_t d_mask;
    uint16_t d_port;
    uint8_t proto;
};

enum {
    MFW_NONE,
    MFW_ADD,
    MFW_REMOVE,
    MFW_VIEW
};

struct mfw_ctl {
    int mode;
    struct mfw_rule rule;
};

static void print_usage() {
    std::cout << "Usage: mf RULE_OPTIONS..\n"
              << "-i --in             input\n"
              << "-o --out            output\n"
              << "-s --s_ip IPADDR    source ip address\n"
              << "-m --s_mask MASK    source mask\n"
              << "-p --s_port PORT    source port\n"
              << "-d --d_ip IPADDR    destination ip address\n"
              << "-n --d_mask MASK    destination mask\n"
              << "-q --d_port PORT    destination port\n"
              << "-c --proto PROTO    protocol\n"
              << "-a --add            add a rule\n"
              << "-r --remove         remove a rule\n"
              << "-v --view           view rules\n"
              << "-h --help           this usage\n";
}

static int64_t parse_number(const char *str, uint32_t min_val, uint32_t max_val) {
    char *end;
    long num = strtol(str, &end, 10);
    if (end == str || num < (long)min_val || num > (long)max_val)
        return -1;
    return num;
}

static void save_rule(const mfw_ctl& ctl) {
    std::ofstream fout(DEVICE_INTF_NAME, std::ios::app | std::ios::binary);
    if (!fout) {
        std::cerr << "Failed to open simulated device file for writing.\n";
        return;
    }
    fout.write(reinterpret_cast<const char*>(&ctl.rule), sizeof(ctl.rule));
    fout.close();
}

static void view_rules() {
    std::ifstream fin(DEVICE_INTF_NAME, std::ios::binary);
    if (!fin) {
        std::cerr << "Failed to open simulated device file for reading.\n";
        return;
    }

    mfw_rule rule;
    struct in_addr addr;

    std::cout << "I/O  "
              << "S_Addr           S_Mask           S_Port "
              << "D_Addr           D_Mask           D_Port Proto\n";

    while (fin.read(reinterpret_cast<char*>(&rule), sizeof(rule))) {
        std::cout << (rule.in ? "In " : "Out");
        addr.s_addr = rule.s_ip;
        std::cout << "  " << inet_ntoa(addr);
        addr.s_addr = rule.s_mask;
        std::cout << "  " << inet_ntoa(addr);
        std::cout << "  " << ntohs(rule.s_port);
        addr.s_addr = rule.d_ip;
        std::cout << "  " << inet_ntoa(addr);
        addr.s_addr = rule.d_mask;
        std::cout << "  " << inet_ntoa(addr);
        std::cout << "  " << ntohs(rule.d_port);
        std::cout << "  " << (int)rule.proto << "\n";
    }

    fin.close();
}

static int parse_arguments(int argc, char **argv, mfw_ctl *ret_ctl) {
    int opt, opt_index;
    int64_t lnum;
    mfw_ctl ctl = {};
    ctl.rule.in = -1;

    static struct option long_options[] = {
        {"in", no_argument, 0, 'i'},
        {"out", no_argument, 0, 'o'},
        {"s_ip", required_argument, 0, 's'},
        {"s_mask", required_argument, 0, 'm'},
        {"s_port", required_argument, 0, 'p'},
        {"d_ip", required_argument, 0, 'd'},
        {"d_mask", required_argument, 0, 'n'},
        {"d_port", required_argument, 0, 'q'},
        {"proto", required_argument, 0, 'c'},
        {"add", no_argument, 0, 'a'},
        {"remove", no_argument, 0, 'r'},
        {"view", no_argument, 0, 'v'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };

    if (argc == 1) {
        print_usage();
        return 0;
    }

    while ((opt = getopt_long(argc, argv, "ios:m:p:d:n:q:c:arvh", long_options, &opt_index)) != -1) {
        switch (opt) {
            case 'i':
                if (ctl.rule.in == 0) {
                    std::cerr << "Choose either in or out.\n";
                    return -1;
                }
                ctl.rule.in = 1;
                break;
            case 'o':
                if (ctl.rule.in == 1) {
                    std::cerr << "Choose either in or out.\n";
                    return -1;
                }
                ctl.rule.in = 0;
                break;
            case 's':
            case 'm':
            case 'd':
            case 'n': {
                struct in_addr addr;
                if (!inet_aton(optarg, &addr)) {
                    std::cerr << "Invalid IP/mask\n";
                    return -1;
                }
                uint32_t addr_val = addr.s_addr;
                switch (opt) {
                    case 's': ctl.rule.s_ip = addr_val; break;
                    case 'm': ctl.rule.s_mask = addr_val; break;
                    case 'd': ctl.rule.d_ip = addr_val; break;
                    case 'n': ctl.rule.d_mask = addr_val; break;
                }
                break;
            }
            case 'p':
                lnum = parse_number(optarg, 0, USHRT_MAX);
                if (lnum < 0) {
                    std::cerr << "Invalid source port\n";
                    return -1;
                }
                ctl.rule.s_port = htons((uint16_t)lnum);
                break;
            case 'q':
                lnum = parse_number(optarg, 0, USHRT_MAX);
                if (lnum < 0) {
                    std::cerr << "Invalid destination port\n";
                    return -1;
                }
                ctl.rule.d_port = htons((uint16_t)lnum);
                break;
            case 'c':
                lnum = parse_number(optarg, 0, UCHAR_MAX);
                if (lnum < 0 || !(lnum == 0 || lnum == IPPROTO_TCP || lnum == IPPROTO_UDP)) {
                    std::cerr << "Invalid protocol\n";
                    return -1;
                }
                ctl.rule.proto = (uint8_t)lnum;
                break;
            case 'a':
                ctl.mode = MFW_ADD;
                break;
            case 'r':
                ctl.mode = MFW_REMOVE; // Not implemented in this version
                break;
            case 'v':
                ctl.mode = MFW_VIEW;
                break;
            case 'h':
            default:
                print_usage();
                return -1;
        }
    }

    if (ctl.mode == MFW_NONE) {
        std::cerr << "Please specify a mode.\n";
        return -1;
    }

    if (ctl.mode != MFW_VIEW && ctl.rule.in == -1) {
        std::cerr << "Specify in or out rule.\n";
        return -1;
    }

    *ret_ctl = ctl;
    return 0;
}

int main(int argc, char **argv) {
    mfw_ctl ctl = {};
    int ret = parse_arguments(argc, argv, &ctl);
    if (ret < 0) return ret;

    switch (ctl.mode) {
        case MFW_ADD:
            save_rule(ctl);
            break;
        case MFW_VIEW:
            view_rules();
            break;
        case MFW_REMOVE:
            std::cout << "[!] Rule removal is not implemented in the simulator version.\n";
            break;
        default:
            break;
    }

    return 0;
}
