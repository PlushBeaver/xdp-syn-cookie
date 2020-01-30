// Library: https://github.com/libbpf/libbpf
// Samples: https://github.com/netoptimizer/prototype-kernel
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include <arpa/inet.h>
#include <linux/bpf.h>
#include <net/if.h>
#include <sys/resource.h>
#include <unistd.h>

#include <cstdio>
#include <ctime>
#include <tuple>
#include <vector>
#include <fcntl.h>

// TODO: configuration
const char PROGRAM[] = "xdp_filter.o";
const char INTERFACE[] = "xdp-local";

// TODO: create interface header for use both in userspace and eBPF
enum Counter {
    COUNTER_INPUT,
    COUNTER_PASS,
    COUNTER_BACK,
    COUNTER_DROP,
    COUNTER_NUM
};

struct Traffic {
    uint64_t packets{};
    uint64_t bytes{};

    Traffic& operator+=(const Traffic& other) {
        packets += other.packets;
        bytes += other.bytes;
        return *this;
    }
};

struct Args {
    enum class Verb {
        Install,
        Watch,
        List,
        Test,
        Add,
        Remove
    };

    std::vector<std::string> raw;
    Verb verb;
    uint32_t ip;

    const std::string& program() const {
        return raw[0];
    }
};

Args parse_args(int argc, const char* argv[]);

class Collector {
    std::vector<Traffic> _datum;

public:
    Collector() {
        // Determine number of CPUs
        const auto cpu_count = ::sysconf(_SC_NPROCESSORS_ONLN);;
        _datum.resize(cpu_count);
    }

    Traffic collect(int map_fd, uint32_t counter_id) {
        // Read from map
        const auto result =
            bpf_map_lookup_elem(map_fd, &counter_id, _datum.data());
        if (result) {
            std::printf("bpf_map_lookup_elem(%d, %u, ...) = %d\n",
                map_fd, counter_id, result);
            return {};
        }

        // Get total from per-CPU datum
        Traffic total;
        for (const auto& data : _datum) {
            total += data;
        }
        return total;
    }
};

int do_load(const Args& args) {
    // Load program
    struct bpf_object* program;
    int prog_fd;
    auto result = bpf_prog_load(PROGRAM, BPF_PROG_TYPE_XDP, &program, &prog_fd);
    std::printf("bpf_prog_load() = %d\n", result);

    // Attach program to device
    // TODO: dont't do it each time
    const auto device_index = ::if_nametoindex(INTERFACE);
    result = bpf_set_link_xdp_fd(device_index, prog_fd, 0);
    if (result < 0) {
        printf("set_link_xdp_fd(%d, %d, 0) = %d\n", device_index, prog_fd, result);
        return 1;
    }

    result = bpf_object__pin_maps(program, "maps");
    if (result < 0) {
        printf("bpf_object__pin_maps() = %d\n", result);
        return 1;
    }

    // TODO: ensure program is loaded on the peer interface (for veth)
    return 0;
}

int do_help(const Args& args) {
    std::fprintf(stderr, "usage: %s {install | watch}\n", args.program().c_str());
    return 0;
}

int do_watch(const Args& args) {
    int map_fd = bpf_obj_get("maps/counters");
    if (map_fd < 0) {
        std::printf("bpf_obj_get() failed\n");
        return 1;
    }

    Collector collector;

    std::printf("time %llu\n", std::time(nullptr));
    for (auto [id, name] : {
            std::make_tuple(COUNTER_PASS, "pass"),
            std::make_tuple(COUNTER_BACK, "back"),
            std::make_tuple(COUNTER_DROP, "drop")}) {
        const auto traffic = collector.collect(map_fd, id);
        std::printf("  %s %llu packets %llu bytes\n",
                name, traffic.packets, traffic.bytes);
    }
    return 0;
}

int do_list_op(const Args& args) {
    int map_fd = bpf_obj_get("maps/clients");
    if (map_fd < 0) {
        std::puts("bpf_obj_get() failed\n");
        return 1;
    }

    switch (args.verb) {
    case Args::Verb::List: {
        uint32_t* key{};
        uint32_t ip;
        while (bpf_map_get_next_key(map_fd, key, &ip) == 0) {
            char text[INET_ADDRSTRLEN + 1]{};
            ::inet_ntop(AF_INET, &ip, text, INET_ADDRSTRLEN);
            std::printf("%s\n", text);

            key = &ip;
        }
        return 0;
    }
    case Args::Verb::Add: {
        uint32_t value{};
        return bpf_map_update_elem(map_fd, &args.ip, &value, BPF_ANY);
    }
    case Args::Verb::Remove:
        return bpf_map_delete_elem(map_fd, &args.ip);
    case Args::Verb::Test: {
        uint32_t value{};
        if (bpf_map_lookup_elem(map_fd, &args.ip, &value) == 0) {
            std::puts("present");
        } else {
            std::puts("absent");
        }
        return 0;
    }
    }
    return 0;
}

int
main(int argc, const char* argv[]) {
    // Increase memory limit (prevents EPERM when loading programs).
    rlimit limit = {RLIM_INFINITY, RLIM_INFINITY};
    if (setrlimit(RLIMIT_MEMLOCK, &limit)) {
        perror("setrlimit(RLIMIT_MEMLOCK, RLIM_INFINITY)");
        return 1;
    }

    // Prerequisites:
    //  mkdir maps
    //  mount -t bpf none maps
    try {
        const auto args = parse_args(argc, argv);
        switch (args.verb) {
        case Args::Verb::Install:
            return do_load(args);
        case Args::Verb::Watch:
            return do_watch(args);
        case Args::Verb::List:
        case Args::Verb::Test:
        case Args::Verb::Add:
        case Args::Verb::Remove:
            return do_list_op(args);
        default:
            return do_help(args);
        }
    } catch (const std::runtime_error& e) {
        std::fprintf(stderr, "%s\n", e.what());
        return EXIT_FAILURE;
    }
}

Args parse_args(int argc, const char* argv[]) {
    Args args{};

    args.raw.resize(argc);
    for (auto i = 0; i < argc; i++) {
        args.raw[i] = argv[i];
    }

    if (args.raw.size() < 2) {
        throw std::runtime_error("args: no verb specified");
    }

    const auto verb = args.raw[1];
    args.verb =
            (verb == "install") ? Args::Verb::Install :
            (verb == "watch") ? Args::Verb::Watch :
            (verb == "list") ? Args::Verb::List :
            (verb == "test") ? Args::Verb::Test :
            (verb == "add") ? Args::Verb::Add :
            (verb == "remove") ? Args::Verb::Remove :
            throw std::runtime_error("args: unknown verb " + verb);

    switch (args.verb) {
    case Args::Verb::Test:
    case Args::Verb::Add:
    case Args::Verb::Remove:
        if (args.raw.size() < 3) {
            throw std::runtime_error("args: verb requires IP argument");
        }
        if (inet_pton(AF_INET, argv[2], &args.ip) != 1) {
            throw std::runtime_error("args: parsing IP address failed");
        }
    }

    return args;
}
