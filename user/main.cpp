#include <iostream>
#include <getopt.h>
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <arpa/inet.h>
#include <unistd.h>
#include <climits>

#include "mfw.h"

void print_usage() {
    std::cout << "Usage: mf [OPTIONS]\n"
              << "MiniFirewall - exact match kernel firewall controller\n"
              << "-i, --in             Input rule\n"
              << "-o, --out            Output rule\n"
              << "-s, --s_ip IPADDR    Source IP\n"
              << "-m, --s_mask MASK    Source subnet mask\n"
              << "-p, --s_port PORT    Source port\n"
              << "-d, --d_ip IPADDR    Destination IP\n"
              << "-n, --d_mask MASK    Destination subnet mask\n"
              << "-q, --d_port PORT    Destination port\n"
              << "-c, --proto PROTO    Protocol (0, 6=TCP, 17=UDP)\n"
              << "-a, --add            Add rule\n"
              << "-r, --remove         Remove rule\n"
              << "-v, --view           View rules\n"
              << "-h, --help           Show help\n";
}

int64_t parse_number(const char* str, uint32_t min, uint32_t max) {
    char* end;
    long num = strtol(str, &end, 10);
    if (end == str || num < (long)min || num > (long)max)
        return -1;
    return num;
}

void send_instruction(const mfw_ctl& ctl) {
    FILE* fp = fopen(DEVICE_INTF_NAME, "w");
    if (!fp) {
        std::cerr << "Error: Cannot open device " << DEVICE_INTF_NAME << std::endl;
        return;
    }

    size_t written = fwrite(&ctl, 1, sizeof(ctl), fp);
    if (written != sizeof(ctl))
        std::cerr << "Warning: Incomplete write to device.\n";

    fclose(fp);
}

void view_rules() {
    FILE* fp = fopen(DEVICE_INTF_NAME, "r");
    if (!fp) {
        std::cerr << "Error: Cannot open device " << DEVICE_INTF_NAME << std::endl;
        return;
    }

    std::cout << "I/O  S_IP             S_Mask           S_Port  D_IP             D_Mask           D_Port  Proto\n";

    mfw_rule rule;
    in_addr addr;
    while (fread(&rule, 1, sizeof(rule), fp) == sizeof(rule)) {
        std::cout << (rule.in ? "In " : "Out") << "  ";

        addr.s_addr = rule.s_ip;
        std::cout << inet_ntoa(addr) << "  ";
        addr.s_addr = rule.s_mask;
        std::cout << inet_ntoa(addr) << "  ";
        std::cout << ntohs(rule.s_port) << "    ";

        addr.s_addr = rule.d_ip;
        std::cout << inet_ntoa(addr) << "  ";
        addr.s_addr = rule.d_mask;
        std::cout << inet_ntoa(addr) << "  ";
        std::cout << ntohs(rule.d_port) << "    ";

        std::cout << static_cast<int>(rule.proto) << "\n";
    }

    fclose(fp);
}

int parse_arguments(int argc, char** argv, mfw_ctl& ctl) {
    int opt, index;
    in_addr addr;
    int64_t num;

    ctl.mode = MFW_NONE;
    ctl.rule.in = -1;

    static struct option long_opts[] = {
        {"in",       no_argument,       0, 'i'},
        {"out",      no_argument,       0, 'o'},
        {"s_ip",     required_argument, 0, 's'},
        {"s_mask",   required_argument, 0, 'm'},
        {"s_port",   required_argument, 0, 'p'},
        {"d_ip",     required_argument, 0, 'd'},
        {"d_mask",   required_argument, 0, 'n'},
        {"d_port",   required_argument, 0, 'q'},
        {"proto",    required_argument, 0, 'c'},
        {"add",      no_argument,       0, 'a'},
        {"remove",   no_argument,       0, 'r'},
        {"view",     no_argument,       0, 'v'},
        {"help",     no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    if (argc == 1) {
        print_usage();
        return -1;
    }

    while ((opt = getopt_long(argc, argv, "ios:m:p:d:n:q:c:arvh", long_opts, &index)) != -1) {
        switch (opt) {
            case 'i':
                if (ctl.rule.in == 0) {
                    std::cerr << "Select only one: in or out.\n";
                    return -1;
                }
                ctl.rule.in = 1;
                break;
            case 'o':
                if (ctl.rule.in == 1) {
                    std::cerr << "Select only one: in or out.\n";
                    return -1;
                }
                ctl.rule.in = 0;
                break;
            case 's':
                if (!inet_aton(optarg, &addr)) {
                    std::cerr << "Invalid source IP.\n";
                    return -1;
                }
                ctl.rule.s_ip = addr.s_addr;
                break;
            case 'm':
                if (!inet_aton(optarg, &addr)) {
                    std::cerr << "Invalid source mask.\n";
                    return -1;
                }
                ctl.rule.s_mask = addr.s_addr;
                break;
            case 'p':
                num = parse_number(optarg, 0, USHRT_MAX);
                if (num < 0) {
                    std::cerr << "Invalid source port.\n";
                    return -1;
                }
                ctl.rule.s_port = htons((uint16_t)num);
                break;
            case 'd':
                if (!inet_aton(optarg, &addr)) {
                    std::cerr << "Invalid destination IP.\n";
                    return -1;
                }
                ctl.rule.d_ip = addr.s_addr;
                break;
            case 'n':
                if (!inet_aton(optarg, &addr)) {
                    std::cerr << "Invalid destination mask.\n";
                    return -1;
                }
                ctl.rule.d_mask = addr.s_addr;
                break;
            case 'q':
                num = parse_number(optarg, 0, USHRT_MAX);
                if (num < 0) {
                    std::cerr << "Invalid destination port.\n";
                    return -1;
                }
                ctl.rule.d_port = htons((uint16_t)num);
                break;
            case 'c':
                num = parse_number(optarg, 0, UCHAR_MAX);
                if (num < 0 || (num != 0 && num != IPPROTO_TCP && num != IPPROTO_UDP)) {
                    std::cerr << "Invalid protocol.\n";
                    return -1;
                }
                ctl.rule.proto = static_cast<uint8_t>(num);
                break;
            case 'a':
                if (ctl.mode != MFW_NONE) {
                    std::cerr << "Only one mode allowed.\n";
                    return -1;
                }
                ctl.mode = MFW_ADD;
                break;
            case 'r':
                if (ctl.mode != MFW_NONE) {
                    std::cerr << "Only one mode allowed.\n";
                    return -1;
                }
                ctl.mode = MFW_REMOVE;
                break;
            case 'v':
                if (ctl.mode != MFW_NONE) {
                    std::cerr << "Only one mode allowed.\n";
                    return -1;
                }
                ctl.mode = MFW_VIEW;
                break;
            case 'h':
            default:
                print_usage();
                return -1;
        }
    }

    if (ctl.mode == MFW_NONE) {
        std::cerr << "Please specify mode --add, --remove, or --view.\n";
        return -1;
    }

    if (ctl.mode != MFW_VIEW && ctl.rule.in == -1) {
        std::cerr << "Please specify direction --in or --out.\n";
        return -1;
    }

    return 0;
}

int main(int argc, char* argv[]) {
    mfw_ctl ctl{};
    if (parse_arguments(argc, argv, ctl) < 0)
        return EXIT_FAILURE;

    switch (ctl.mode) {
        case MFW_ADD:
        case MFW_REMOVE:
            send_instruction(ctl);
            break;
        case MFW_VIEW:
            view_rules();
            break;
        default:
            break;
    }

    return 0;
}
