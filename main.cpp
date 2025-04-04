#include <iostream>
#include <fstream>
#include <getopt.h>
#include <string>
#include <arpa/inet.h>
#include <cstring>
#include <cstdlib>
#include <climits>

#include "mfw.h"

using namespace std;

static void print_usage() {
    cout << "Usage: mf RULE_OPTIONS..\n"
         << "MiniFirewall implements an exact match algorithm.\n"
         << "-i --in               Input\n"
         << "-o --out              Output\n"
         << "--v4                  Use IPv4 (default)\n"
         << "--v6                  Use IPv6\n"
         << "-s --s_ip IPADDR      Source IP\n"
         << "-m --s_mask MASK      Source Mask\n"
         << "-p --s_port PORT      Source Port\n"
         << "-d --d_ip IPADDR      Destination IP\n"
         << "-n --d_mask MASK      Destination Mask\n"
         << "-q --d_port PORT      Destination Port\n"
         << "-c --proto PROTO      Protocol (0, TCP=6, UDP=17)\n"
         << "-a --add              Add a rule\n"
         << "-r --remove           Remove a rule\n"
         << "-v --view             View rules\n"
         << "-h --help             This usage\n";
}

static int64_t parse_number(const char* str, uint32_t min, uint32_t max) {
    char* end;
    long val = strtol(str, &end, 10);
    if (end == str || val < min || val > max)
        return -1;
    return val;
}

static void send_instruction(struct mfw_ctl* ctl) {
    ofstream dev(DEVICE_PATH, ios::binary | ios::out);
    if (!dev) {
        cerr << "Cannot open device file " << DEVICE_PATH << endl;
        return;
    }
    dev.write(reinterpret_cast<const char*>(ctl), sizeof(*ctl));
    if (!dev) {
        cerr << "Write failed.\n";
    }
    dev.close();
}

static void view_rules() {
    ifstream dev(DEVICE_PATH, ios::binary | ios::in);
    if (!dev) {
        cerr << "Cannot open device file " << DEVICE_PATH << endl;
        return;
    }

    struct mfw_rule rule;
    cout << "I/O  IPv  S_Addr                  S_Mask                  S_Port "
         << "D_Addr                  D_Mask                  D_Port Proto\n";

    while (dev.read(reinterpret_cast<char*>(&rule), sizeof(rule))) {
        cout << (rule.in ? "In " : "Out") << "  ";
        cout << (int)rule.ip_version << "     ";

        char ip_str[INET6_ADDRSTRLEN];

        if (rule.ip_version == 4) {
            inet_ntop(AF_INET, &rule.s_ip4, ip_str, sizeof(ip_str));
            cout << ip_str << string(22 - strlen(ip_str), ' ');
            inet_ntop(AF_INET, &rule.s_mask4, ip_str, sizeof(ip_str));
            cout << ip_str << string(22 - strlen(ip_str), ' ');
        } else {
            inet_ntop(AF_INET6, rule.s_ip6, ip_str, sizeof(ip_str));
            cout << ip_str << string(22 - strlen(ip_str), ' ');
            inet_ntop(AF_INET6, rule.s_mask6, ip_str, sizeof(ip_str));
            cout << ip_str << string(22 - strlen(ip_str), ' ');
        }

        cout << ntohs(rule.s_port) << "     ";

        if (rule.ip_version == 4) {
            inet_ntop(AF_INET, &rule.d_ip4, ip_str, sizeof(ip_str));
            cout << ip_str << string(22 - strlen(ip_str), ' ');
            inet_ntop(AF_INET, &rule.d_mask4, ip_str, sizeof(ip_str));
            cout << ip_str << string(22 - strlen(ip_str), ' ');
        } else {
            inet_ntop(AF_INET6, rule.d_ip6, ip_str, sizeof(ip_str));
            cout << ip_str << string(22 - strlen(ip_str), ' ');
            inet_ntop(AF_INET6, rule.d_mask6, ip_str, sizeof(ip_str));
            cout << ip_str << string(22 - strlen(ip_str), ' ');
        }

        cout << ntohs(rule.d_port) << "     ";
        cout << (int)rule.proto << endl;
    }

    dev.close();
}

int parse_arguments(int argc, char** argv, struct mfw_ctl* ret_ctl) {
    int opt;
    int64_t lnum;
    struct in_addr addr4;
    struct in6_addr addr6;
    struct mfw_ctl ctl = {};
    ctl.rule.in = -1;
    ctl.rule.ip_version = 4;

    static struct option long_options[] = {
        {"in", no_argument, 0, 'i'},
        {"out", no_argument, 0, 'o'},
        {"v4", no_argument, 0, 1},
        {"v6", no_argument, 0, 2},
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

    while ((opt = getopt_long(argc, argv, "ios:m:p:d:n:q:c:arvh", long_options, nullptr)) != -1) {
        switch (opt) {
        case 'i': ctl.rule.in = 1; break;
        case 'o': ctl.rule.in = 0; break;
        case 1: ctl.rule.ip_version = 4; break;
        case 2: ctl.rule.ip_version = 6; break;
        case 's':
            if (ctl.rule.ip_version == 4) {
                if (inet_pton(AF_INET, optarg, &addr4) != 1) {
                    cerr << "Invalid IPv4 source address.\n"; return -1;
                }
                ctl.rule.s_ip4 = addr4.s_addr;
            } else {
                if (inet_pton(AF_INET6, optarg, &addr6) != 1) {
                    cerr << "Invalid IPv6 source address.\n"; return -1;
                }
                memcpy(ctl.rule.s_ip6, addr6.s6_addr, 16);
            }
            break;
        case 'm':
            if (ctl.rule.ip_version == 4) {
                if (inet_pton(AF_INET, optarg, &addr4) != 1) {
                    cerr << "Invalid IPv4 source mask.\n"; return -1;
                }
                ctl.rule.s_mask4 = addr4.s_addr;
            } else {
                if (inet_pton(AF_INET6, optarg, &addr6) != 1) {
                    cerr << "Invalid IPv6 source mask.\n"; return -1;
                }
                memcpy(ctl.rule.s_mask6, addr6.s6_addr, 16);
            }
            break;
        case 'p':
            lnum = parse_number(optarg, 0, USHRT_MAX);
            if (lnum < 0) { cerr << "Invalid source port\n"; return -1; }
            ctl.rule.s_port = htons((uint16_t)lnum); break;
        case 'd':
            if (ctl.rule.ip_version == 4) {
                if (inet_pton(AF_INET, optarg, &addr4) != 1) {
                    cerr << "Invalid IPv4 dest address.\n"; return -1;
                }
                ctl.rule.d_ip4 = addr4.s_addr;
            } else {
                if (inet_pton(AF_INET6, optarg, &addr6) != 1) {
                    cerr << "Invalid IPv6 dest address.\n"; return -1;
                }
                memcpy(ctl.rule.d_ip6, addr6.s6_addr, 16);
            }
            break;
        case 'n':
            if (ctl.rule.ip_version == 4) {
                if (inet_pton(AF_INET, optarg, &addr4) != 1) {
                    cerr << "Invalid IPv4 dest mask.\n"; return -1;
                }
                ctl.rule.d_mask4 = addr4.s_addr;
            } else {
                if (inet_pton(AF_INET6, optarg, &addr6) != 1) {
                    cerr << "Invalid IPv6 dest mask.\n"; return -1;
                }
                memcpy(ctl.rule.d_mask6, addr6.s6_addr, 16);
            }
            break;
        case 'q':
            lnum = parse_number(optarg, 0, USHRT_MAX);
            if (lnum < 0) { cerr << "Invalid dest port\n"; return -1; }
            ctl.rule.d_port = htons((uint16_t)lnum); break;
        case 'c':
            lnum = parse_number(optarg, 0, UCHAR_MAX);
            if (lnum < 0 || !(lnum == 0 || lnum == IPPROTO_TCP || lnum == IPPROTO_UDP)) {
                cerr << "Invalid protocol\n"; return -1;
            }
            ctl.rule.proto = (uint8_t)lnum; break;
        case 'a': ctl.mode = MFW_ADD; break;
        case 'r': ctl.mode = MFW_REMOVE; break;
        case 'v': ctl.mode = MFW_VIEW; break;
        case 'h': default: print_usage(); return -1;
        }
    }

    if (ctl.mode != MFW_VIEW && ctl.rule.in == -1) {
        cerr << "Specify --in or --out\n"; return -1;
    }

    *ret_ctl = ctl;
    return 0;
}

int main(int argc, char** argv) {
    struct mfw_ctl ctl;
    if (parse_arguments(argc, argv, &ctl) < 0)
        return 1;

    switch (ctl.mode) {
    case MFW_ADD:
    case MFW_REMOVE:
        send_instruction(&ctl);
        break;
    case MFW_VIEW:
        view_rules();
        break;
    default:
        break;
    }
    return 0;
}
