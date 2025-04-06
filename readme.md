## 🔥 MiniFirewall – Unified IPv4 & IPv6 Kernel Firewall

MiniFirewall is a lightweight kernel-space firewall that supports **IPv4 and IPv6 rules**, allowing you to **add**, **remove**, and **view** exact-match rules via a user-space CLI tool (`mfw`). Built with performance and modularity in mind, it uses a character device `/dev/mfw` to communicate between kernel and user space.

---

## 📁 Project Structure

```
MiniFirewall/
│
├── kernel/
│   ├── mfw_kmod.c       # Kernel module source
│   └── mfw_kmod.h       # Kernel module header
│
├── user/
│   └── main.cpp         # User-space firewall CLI
│
├── mfw.h                # Shared user/kernel structure definition
├── Makefile             # Unified Makefile to build everything
├── README.md            # You are here
└── build/               # Built kernel module and CLI tool
```

---

## ⚙️ Features

- ✅ **Unified IPv4 + IPv6 rule structure**
- ✅ Add/remove rules with strict matching
- ✅ View active rules (kernel → user)
- ✅ Lightweight & fast
- ✅ Built as a Linux kernel module
- ✅ Simple C++ user interface with `getopt_long` CLI parsing

---

## 🧱 Building the Project

### 🔧 Prerequisites

```bash
sudo apt install build-essential linux-headers-$(uname -r)
```

### 🔨 Build Everything

```bash
make
```

### 🧹 Clean the Build

```bash
make clean
```

---

## 📦 Running It

### 🔌 Load the Kernel Module

```bash
sudo insmod build/mfw_kmod.ko
```

Check if it’s loaded:

```bash
lsmod | grep mfw_kmod
```

### 🧪 Use the CLI Tool

#### 1️⃣ Add Rule

```bash
sudo ./build/mfw --in --s_ip 192.168.0.10 --s_mask 255.255.255.0 \
  --s_port 8080 --d_ip 10.0.0.2 --d_mask 255.255.255.0 --d_port 443 \
  --proto 6 --add
```

#### 2️⃣ View Rules

```bash
sudo ./build/mfw --view
```

#### 3️⃣ Remove Rule

Just use the same rule fields with `--remove`:

```bash
sudo ./build/mfw --in --s_ip 192.168.0.10 --s_mask 255.255.255.0 \
  --s_port 8080 --d_ip 10.0.0.2 --d_mask 255.255.255.0 --d_port 443 \
  --proto 6 --remove
```

---

## 🛑 Unloading the Module

```bash
sudo rmmod mfw_kmod
```

---

## 📌 Notes

- `/dev/mfw` is created when the module loads and used by the CLI to send/receive instructions.
- IPv6 fields are present in the rule struct but optional (can be extended further).
- Uses exact match for all fields; incomplete fields are ignored.

---

## 🚀 Future Enhancements

- [ ] Support wildcard (`*`) matching
- [ ] Logging firewall hits (kernel → dmesg or /proc)
- [ ] Persistent rule storage
- [ ] Netfilter hook integration (currently rule-only)

---

## 🧑‍💻 Author

Made by **Aman Naveen,Mayank Kataria, Vansh Nain**  
BSc (Hons) Computer Science – Ramanujan College, Delhi University

---
