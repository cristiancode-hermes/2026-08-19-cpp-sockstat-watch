// SPDX-License-Identifier: MIT
// cpp-sockstat-watch — Linux socket statistics monitor (/proc/net/sockstat + sockstat6)
// Build: g++ -std=c++23 -O2 -Wall -Wextra src/main.cpp -o sockstat-watch
// Usage: ./sockstat-watch [--watch N] [--json] [--demo] [--no-color] [--selftest]

#include <algorithm>
#include <charconv>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <expected>
#include <fstream>
#include <iostream>
#include <map>
#include <optional>
#include <print>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

// ── Types ──

struct Error {
  int code;
  std::string message;
};

template <typename T>
using Result = std::expected<T, Error>;

struct ProtoStats {
  std::string name;          // TCP, UDP, TCP6, ...
  long long inuse{0};        // sockets currently in use
  long long orphan{0};       // orphaned TCP sockets (-1 if N/A)
  long long tw{0};           // TIME_WAIT (-1 if N/A)
  long long alloc{0};        // allocated sockets (-1 if N/A)
  long long mem_pages{0};    // memory pages (-1 if N/A)
  long long memory{0};       // FRAG memory bytes (-1 if N/A)
  bool has_orphan{false};
  bool has_tw{false};
  bool has_alloc{false};
  bool has_mem{false};
  bool has_memory{false};
};

struct SockSnapshot {
  long long sockets_used{0};
  std::vector<ProtoStats> protos;
  long long total_inuse{0};
  long long total_tw{0};
  long long total_orphan{0};
  long long total_mem_pages{0};
  double timestamp{0.0};
  // deltas vs previous (watch mode)
  long long d_sockets{0};
  long long d_inuse{0};
  long long d_tw{0};
  long long d_orphan{0};
  bool has_delta{false};
};

// ── Mutable ANSI palette (--no-color empties every code) ──

bool g_color = true;
std::string C_RST, C_BOLD, C_DIM, C_CYAN, C_GREEN, C_YELLOW, C_RED, C_MAGENTA, C_BLUE;

void init_colors() {
  C_RST     = g_color ? "\033[0m"  : "";
  C_BOLD    = g_color ? "\033[1m"  : "";
  C_DIM     = g_color ? "\033[2m"  : "";
  C_CYAN    = g_color ? "\033[36m" : "";
  C_GREEN   = g_color ? "\033[32m" : "";
  C_YELLOW  = g_color ? "\033[33m" : "";
  C_RED     = g_color ? "\033[31m" : "";
  C_MAGENTA = g_color ? "\033[35m" : "";
  C_BLUE    = g_color ? "\033[34m" : "";
}

// ── Helpers ──

static long long parse_ll(std::string_view s) {
  while (!s.empty() && (s.front() == ' ' || s.front() == '\t')) s.remove_prefix(1);
  while (!s.empty() && (s.back() == ' ' || s.back() == '\t' || s.back() == '\n' || s.back() == '\r'))
    s.remove_suffix(1);
  if (s.empty()) return 0;
  long long v = 0;
  auto [ptr, ec] = std::from_chars(s.data(), s.data() + s.size(), v);
  if (ec != std::errc{}) return 0;
  return v;
}

static std::string fmt_signed(long long v) {
  char buf[32];
  if (v > 0) std::snprintf(buf, sizeof(buf), "+%lld", v);
  else std::snprintf(buf, sizeof(buf), "%lld", v);
  return buf;
}

static std::string fmt_pages_kb(long long pages) {
  // sockstat mem is in pages (typically 4 KiB)
  if (pages < 0) return "n/a";
  long long kib = pages * 4;
  char buf[32];
  if (kib >= 1024 * 1024) {
    std::snprintf(buf, sizeof(buf), "%.2f GiB", kib / (1024.0 * 1024.0));
  } else if (kib >= 1024) {
    std::snprintf(buf, sizeof(buf), "%.1f MiB", kib / 1024.0);
  } else {
    std::snprintf(buf, sizeof(buf), "%lld KiB", kib);
  }
  return buf;
}

static std::string tw_color(long long tw) {
  if (tw > 5000) return C_RED;
  if (tw > 500) return C_YELLOW;
  if (tw > 0) return C_GREEN;
  return C_DIM;
}

static std::string make_bar(double pct, int width = 20) {
  int filled = std::clamp(static_cast<int>(std::round(pct / 100.0 * width)), 0, width);
  std::string bar;
  bar += C_BOLD;
  if (pct > 80.0) bar += C_RED;
  else if (pct > 50.0) bar += C_YELLOW;
  else bar += C_GREEN;
  bar += std::string(filled, '|');
  bar += C_DIM;
  bar += std::string(width - filled, '.');
  bar += C_RST;
  return bar;
}

static std::string escape_json(const std::string& s) {
  std::string out;
  out.reserve(s.size() + 8);
  for (char c : s) {
    switch (c) {
      case '"':  out += "\\\""; break;
      case '\\': out += "\\\\"; break;
      case '\n': out += "\\n"; break;
      default:   out += c; break;
    }
  }
  return out;
}

// ── Parsers ──

// Parse a sockstat-style line:
//   "TCP: inuse 20 orphan 0 tw 46 alloc 107 mem 46"
//   "sockets: used 120"
//   "FRAG: inuse 0 memory 0"
static ProtoStats parse_proto_line(const std::string& line) {
  ProtoStats p;
  auto colon = line.find(':');
  if (colon == std::string::npos) return p;

  p.name = line.substr(0, colon);
  // trim trailing spaces on name
  while (!p.name.empty() && (p.name.back() == ' ' || p.name.back() == '\t'))
    p.name.pop_back();

  std::istringstream ss(line.substr(colon + 1));
  std::string key;
  std::string val;
  while (ss >> key >> val) {
    long long n = parse_ll(val);
    if (key == "used" || key == "inuse") {
      p.inuse = n;
    } else if (key == "orphan") {
      p.orphan = n;
      p.has_orphan = true;
    } else if (key == "tw") {
      p.tw = n;
      p.has_tw = true;
    } else if (key == "alloc") {
      p.alloc = n;
      p.has_alloc = true;
    } else if (key == "mem") {
      p.mem_pages = n;
      p.has_mem = true;
    } else if (key == "memory") {
      p.memory = n;
      p.has_memory = true;
    }
  }
  return p;
}

Result<SockSnapshot> read_sockstat(const std::string& path4 = "/proc/net/sockstat",
                                   const std::string& path6 = "/proc/net/sockstat6") {
  SockSnapshot snap;
  auto now = std::chrono::system_clock::now();
  snap.timestamp = std::chrono::duration<double>(now.time_since_epoch()).count();

  auto read_file = [&](const std::string& path, bool is_v4) -> Result<void> {
    std::ifstream f(path);
    if (!f.is_open()) {
      return std::unexpected(Error{404, "cannot open " + path});
    }
    std::string line;
    while (std::getline(f, line)) {
      if (line.empty()) continue;
      auto p = parse_proto_line(line);
      if (p.name.empty()) continue;
      if (is_v4 && p.name == "sockets") {
        snap.sockets_used = p.inuse;
        continue;
      }
      snap.protos.push_back(std::move(p));
    }
    return {};
  };

  auto r4 = read_file(path4, true);
  if (!r4) return std::unexpected(r4.error());

  // IPv6 is optional (some minimal containers omit sockstat6)
  {
    std::ifstream f6(path6);
    if (f6.is_open()) {
      std::string line;
      while (std::getline(f6, line)) {
        if (line.empty()) continue;
        auto p = parse_proto_line(line);
        if (!p.name.empty()) snap.protos.push_back(std::move(p));
      }
    }
  }

  if (snap.protos.empty() && snap.sockets_used == 0) {
    return std::unexpected(Error{500, "no socket stats parsed from " + path4});
  }

  for (const auto& p : snap.protos) {
    snap.total_inuse += p.inuse;
    if (p.has_tw) snap.total_tw += p.tw;
    if (p.has_orphan) snap.total_orphan += p.orphan;
    if (p.has_mem) snap.total_mem_pages += p.mem_pages;
  }
  return snap;
}

// ── Demo data ──

SockSnapshot build_demo_snapshot() {
  SockSnapshot snap;
  auto now = std::chrono::system_clock::now();
  snap.timestamp = std::chrono::duration<double>(now.time_since_epoch()).count();
  snap.sockets_used = 842;

  auto add = [&](std::string name, long long inuse, long long orphan, long long tw,
                 long long alloc, long long mem, bool tcp_like) {
    ProtoStats p;
    p.name = std::move(name);
    p.inuse = inuse;
    if (tcp_like) {
      p.orphan = orphan; p.has_orphan = true;
      p.tw = tw; p.has_tw = true;
      p.alloc = alloc; p.has_alloc = true;
    }
    p.mem_pages = mem; p.has_mem = true;
    snap.protos.push_back(std::move(p));
  };

  add("TCP", 186, 2, 1240, 412, 98, true);
  add("UDP", 14, 0, 0, 0, 12, false);
  {
    ProtoStats u;
    u.name = "UDPLITE";
    u.inuse = 0;
    snap.protos.push_back(std::move(u));
  }
  {
    ProtoStats r;
    r.name = "RAW";
    r.inuse = 1;
    snap.protos.push_back(std::move(r));
  }
  {
    ProtoStats f;
    f.name = "FRAG";
    f.inuse = 0;
    f.memory = 0;
    f.has_memory = true;
    snap.protos.push_back(std::move(f));
  }
  add("TCP6", 94, 0, 310, 180, 44, true);
  add("UDP6", 6, 0, 0, 0, 4, false);
  {
    ProtoStats u;
    u.name = "UDPLITE6";
    u.inuse = 0;
    snap.protos.push_back(std::move(u));
  }
  {
    ProtoStats r;
    r.name = "RAW6";
    r.inuse = 0;
    snap.protos.push_back(std::move(r));
  }
  {
    ProtoStats f;
    f.name = "FRAG6";
    f.inuse = 0;
    f.memory = 0;
    f.has_memory = true;
    snap.protos.push_back(std::move(f));
  }

  for (const auto& p : snap.protos) {
    snap.total_inuse += p.inuse;
    if (p.has_tw) snap.total_tw += p.tw;
    if (p.has_orphan) snap.total_orphan += p.orphan;
    if (p.has_mem) snap.total_mem_pages += p.mem_pages;
  }
  return snap;
}

// ── Output ──

void print_header(const SockSnapshot& snap) {
  std::cout << C_BOLD << C_CYAN;
  std::cout << "+================================================+\n";
  std::cout << "|     Linux Socket Statistics Monitor            |\n";
  std::cout << "+================================================+" << C_RST << "\n";
  std::cout << C_DIM << "  Source: /proc/net/sockstat + sockstat6" << C_RST << "\n";
  char tbuf[64];
  std::time_t tt = static_cast<std::time_t>(snap.timestamp);
  std::tm tm{};
  localtime_r(&tt, &tm);
  std::strftime(tbuf, sizeof(tbuf), "%Y-%m-%d %H:%M:%S", &tm);
  std::cout << C_DIM << "  Snapshot: " << tbuf << C_RST << "\n\n";
}

void print_summary(const SockSnapshot& snap) {
  std::cout << C_BOLD << "  -- Aggregate --" << C_RST << "\n";
  std::cout << "  Sockets used:  " << C_CYAN << snap.sockets_used << C_RST;
  if (snap.has_delta) {
    std::cout << "  (" << (snap.d_sockets >= 0 ? C_GREEN : C_RED)
              << fmt_signed(snap.d_sockets) << C_RST << ")";
  }
  std::cout << "\n";

  std::cout << "  Proto inuse:   " << C_GREEN << snap.total_inuse << C_RST;
  if (snap.has_delta) {
    std::cout << "  (" << (snap.d_inuse >= 0 ? C_GREEN : C_RED)
              << fmt_signed(snap.d_inuse) << C_RST << ")";
  }
  std::cout << "\n";

  std::cout << "  TIME_WAIT:     " << tw_color(snap.total_tw) << snap.total_tw << C_RST;
  if (snap.has_delta) {
    std::cout << "  (" << (snap.d_tw >= 0 ? C_YELLOW : C_GREEN)
              << fmt_signed(snap.d_tw) << C_RST << ")";
  }
  std::cout << "\n";

  std::cout << "  Orphans:       " << (snap.total_orphan > 0 ? C_YELLOW : C_DIM)
            << snap.total_orphan << C_RST;
  if (snap.has_delta) {
    std::cout << "  (" << fmt_signed(snap.d_orphan) << ")";
  }
  std::cout << "\n";

  std::cout << "  Sock mem:      " << C_MAGENTA << fmt_pages_kb(snap.total_mem_pages)
            << C_RST << C_DIM << " (" << snap.total_mem_pages << " pages)" << C_RST << "\n";

  // Pressure bar: TIME_WAIT relative to a soft threshold of 2000
  double tw_pct = std::min(100.0, 100.0 * static_cast<double>(snap.total_tw) / 2000.0);
  std::cout << "  TW pressure:   " << make_bar(tw_pct) << " "
            << C_DIM << "(" << static_cast<int>(tw_pct) << "% of soft limit 2000)" << C_RST << "\n\n";
}

void print_table(const SockSnapshot& snap) {
  std::cout << C_BOLD << "  -- Protocols --" << C_RST << "\n";
  std::cout << "  " << C_DIM
            << "Proto      inuse   orphan       tw    alloc       mem"
            << C_RST << "\n";
  std::cout << "  " << C_DIM << std::string(58, '-') << C_RST << "\n";

  for (const auto& p : snap.protos) {
    char line[128];
    auto na = [&](bool has, long long v) -> std::string {
      if (!has) return "      -";
      char b[16];
      std::snprintf(b, sizeof(b), "%7lld", v);
      return b;
    };

    std::snprintf(line, sizeof(line), "  %-9s %7lld", p.name.c_str(), p.inuse);
    std::cout << C_CYAN << line << C_RST;

    // orphan
    if (p.has_orphan) {
      std::cout << "  " << (p.orphan > 0 ? C_YELLOW : C_DIM);
      std::snprintf(line, sizeof(line), "%7lld", p.orphan);
      std::cout << line << C_RST;
    } else {
      std::cout << C_DIM << "        -" << C_RST;
    }

    // tw
    if (p.has_tw) {
      std::cout << "  " << tw_color(p.tw);
      std::snprintf(line, sizeof(line), "%7lld", p.tw);
      std::cout << line << C_RST;
    } else {
      std::cout << C_DIM << "        -" << C_RST;
    }

    // alloc
    std::cout << C_DIM << na(p.has_alloc, p.alloc) << C_RST;

    // mem
    if (p.has_mem) {
      std::cout << "  " << C_MAGENTA;
      std::snprintf(line, sizeof(line), "%7lld", p.mem_pages);
      std::cout << line << C_RST;
    } else if (p.has_memory) {
      std::cout << "  " << C_MAGENTA;
      std::snprintf(line, sizeof(line), "%7lld", p.memory);
      std::cout << line << C_RST;
    } else {
      std::cout << C_DIM << "        -" << C_RST;
    }
    std::cout << "\n";
  }
  std::cout << "\n";

  std::cout << C_DIM
            << "  Notes: mem = kernel pages (x4 KiB); tw = TCP TIME_WAIT; orphan = unowned TCP\n"
            << "  High TIME_WAIT can exhaust ephemeral ports under heavy short-lived traffic."
            << C_RST << "\n";
}

void print_json(const SockSnapshot& snap) {
  std::ostringstream j;
  j << "{\n";
  j << "  \"timestamp\": " << std::to_string(snap.timestamp) << ",\n";
  j << "  \"sockets_used\": " << snap.sockets_used << ",\n";
  j << "  \"total_inuse\": " << snap.total_inuse << ",\n";
  j << "  \"total_tw\": " << snap.total_tw << ",\n";
  j << "  \"total_orphan\": " << snap.total_orphan << ",\n";
  j << "  \"total_mem_pages\": " << snap.total_mem_pages << ",\n";
  j << "  \"total_mem_kib\": " << (snap.total_mem_pages * 4) << ",\n";
  if (snap.has_delta) {
    j << "  \"delta\": {\n";
    j << "    \"sockets\": " << snap.d_sockets << ",\n";
    j << "    \"inuse\": " << snap.d_inuse << ",\n";
    j << "    \"tw\": " << snap.d_tw << ",\n";
    j << "    \"orphan\": " << snap.d_orphan << "\n";
    j << "  },\n";
  }
  j << "  \"protocols\": [\n";
  for (size_t i = 0; i < snap.protos.size(); ++i) {
    const auto& p = snap.protos[i];
    j << "    {\"name\":\"" << escape_json(p.name) << "\"";
    j << ",\"inuse\":" << p.inuse;
    if (p.has_orphan) j << ",\"orphan\":" << p.orphan;
    if (p.has_tw) j << ",\"tw\":" << p.tw;
    if (p.has_alloc) j << ",\"alloc\":" << p.alloc;
    if (p.has_mem) j << ",\"mem_pages\":" << p.mem_pages;
    if (p.has_memory) j << ",\"memory\":" << p.memory;
    j << "}";
    if (i + 1 < snap.protos.size()) j << ",";
    j << "\n";
  }
  j << "  ]\n}";
  std::println(std::cout, "{}", j.str());
}

// ── Self-test ──

int run_selftest() {
  int passed = 0, failed = 0;
  auto check = [&](const char* name, bool cond) {
    if (cond) {
      std::println(std::cout, "  {}✓{} {}", C_GREEN, C_RST, name);
      passed++;
    } else {
      std::println(std::cout, "  {}✗{} {}", C_RED, C_RST, name);
      failed++;
    }
  };

  std::println(std::cout, "{}", C_BOLD + "  Running self-tests..." + C_RST);

  // parse helpers
  check("parse_ll('  42') == 42", parse_ll("  42") == 42);
  check("parse_ll('0') == 0", parse_ll("0") == 0);
  check("fmt_signed(5) == '+5'", fmt_signed(5) == "+5");
  check("fmt_signed(-3) == '-3'", fmt_signed(-3) == "-3");
  check("fmt_pages_kb(256) contains KiB or MiB",
        fmt_pages_kb(256).find("KiB") != std::string::npos ||
        fmt_pages_kb(256).find("MiB") != std::string::npos);

  // line parser
  {
    auto p = parse_proto_line("TCP: inuse 20 orphan 0 tw 46 alloc 107 mem 46");
    check("parse TCP name", p.name == "TCP");
    check("parse TCP inuse", p.inuse == 20);
    check("parse TCP tw", p.has_tw && p.tw == 46);
    check("parse TCP orphan", p.has_orphan && p.orphan == 0);
    check("parse TCP alloc", p.has_alloc && p.alloc == 107);
    check("parse TCP mem", p.has_mem && p.mem_pages == 46);
  }
  {
    auto p = parse_proto_line("sockets: used 120");
    check("parse sockets used as inuse", p.name == "sockets" && p.inuse == 120);
  }
  {
    auto p = parse_proto_line("FRAG6: inuse 0 memory 0");
    check("parse FRAG6 memory field", p.name == "FRAG6" && p.has_memory && p.memory == 0);
  }

  // demo snapshot
  auto demo = build_demo_snapshot();
  check("demo sockets_used > 0", demo.sockets_used > 0);
  check("demo has TCP + TCP6", [&] {
    bool tcp = false, tcp6 = false;
    for (auto& p : demo.protos) {
      if (p.name == "TCP") tcp = true;
      if (p.name == "TCP6") tcp6 = true;
    }
    return tcp && tcp6;
  }());
  check("demo total_tw > 0", demo.total_tw > 0);
  check("demo total_inuse == sum", [&] {
    long long s = 0;
    for (auto& p : demo.protos) s += p.inuse;
    return s == demo.total_inuse;
  }());

  // print no crash
  bool print_ok = true;
  try {
    print_header(demo);
    print_summary(demo);
    print_table(demo);
  } catch (...) {
    print_ok = false;
  }
  check("demo print no crash", print_ok);

  // JSON
  std::string json_out;
  {
    std::ostringstream oss;
    auto* old = std::cout.rdbuf(oss.rdbuf());
    print_json(demo);
    std::cout.rdbuf(old);
    json_out = oss.str();
  }
  check("JSON starts with '{'", !json_out.empty() && json_out[0] == '{');
  check("JSON has protocols", json_out.find("\"protocols\"") != std::string::npos);
  check("JSON has total_tw", json_out.find("\"total_tw\"") != std::string::npos);
  check("JSON has TCP name", json_out.find("\"name\":\"TCP\"") != std::string::npos);

  // real /proc read
  auto real = read_sockstat();
  if (real.has_value()) {
    check("proc sockstat read ok", true);
    check("real sockets_used >= 0", real->sockets_used >= 0);
    check("real has at least one proto", !real->protos.empty());
  } else {
    std::println(std::cout, "  {}ℹ{} /proc read failed ({}): restricted env — skipping",
                 C_YELLOW, C_RST, real.error().message);
  }

  // --no-color
  g_color = true;
  init_colors();
  std::string colored = tw_color(1000);
  g_color = false;
  init_colors();
  std::string plain = tw_color(1000);
  check("--no-color clears ANSI", colored != plain && plain.empty());
  g_color = true;
  init_colors();

  std::println(std::cout, "");
  std::println(std::cout, "{}  Results: {} passed, {} failed{}",
               failed == 0 ? C_GREEN : C_RED, passed, failed, C_RST);
  return failed == 0 ? 0 : 1;
}

// ── Main ──

int main(int argc, char** argv) {
  bool json_mode = false;
  bool watch_mode = false;
  bool demo_mode = false;
  bool selftest = false;
  int watch_secs = 2;

  for (int i = 1; i < argc; ++i) {
    std::string_view arg{argv[i]};
    if (arg == "--json") json_mode = true;
    else if (arg == "--no-color" || arg == "-c") { g_color = false; }
    else if (arg == "--demo") demo_mode = true;
    else if (arg == "--selftest") selftest = true;
    else if ((arg == "--watch" || arg == "-w") && i + 1 < argc) {
      watch_mode = true;
      ++i;
      std::from_chars(argv[i], argv[i] + std::strlen(argv[i]), watch_secs);
      if (watch_secs < 1) watch_secs = 1;
    } else if (arg == "--help" || arg == "-h") {
      init_colors();
      std::println(std::cout, "{}sockstat-watch{} — Linux socket statistics monitor\n",
                   C_BOLD, C_RST);
      std::println(std::cout, "Usage: sockstat-watch [options]\n");
      std::println(std::cout, "Options:");
      std::println(std::cout, "  -w, --watch N   Refresh every N seconds (default: 2)");
      std::println(std::cout, "  --json          Output JSON");
      std::println(std::cout, "  --no-color, -c  Disable ANSI colors");
      std::println(std::cout, "  --demo          Simulated high-load socket data");
      std::println(std::cout, "  --selftest      Run built-in tests");
      std::println(std::cout, "  -h, --help      Show this help\n");
      std::println(std::cout, "{}", C_DIM + "Reads: /proc/net/sockstat, /proc/net/sockstat6" + C_RST);
      std::println(std::cout, "{}",
                   C_DIM + "Fields: sockets used, TCP/UDP inuse, orphan, tw, alloc, mem pages" + C_RST);
      return 0;
    }
  }

  init_colors();
  if (selftest) return run_selftest();

  auto take = [&]() -> std::optional<SockSnapshot> {
    if (demo_mode) return build_demo_snapshot();
    auto r = read_sockstat();
    if (!r) {
      if (!json_mode) {
        std::println(std::cerr, "{}Error:{} {}", C_RED, C_RST, r.error().message);
      }
      return std::nullopt;
    }
    return *r;
  };

  if (watch_mode) {
    std::optional<SockSnapshot> prev;
    bool first = true;
    while (true) {
      auto snap = take();
      if (!snap) return 1;

      if (prev) {
        snap->d_sockets = snap->sockets_used - prev->sockets_used;
        snap->d_inuse = snap->total_inuse - prev->total_inuse;
        snap->d_tw = snap->total_tw - prev->total_tw;
        snap->d_orphan = snap->total_orphan - prev->total_orphan;
        snap->has_delta = true;
      }
      prev = snap;

      if (!json_mode && !first) {
        std::cout << "\033[2J\033[H";
      }
      first = false;

      if (json_mode) {
        print_json(*snap);
      } else {
        print_header(*snap);
        print_summary(*snap);
        print_table(*snap);
        std::println(std::cout, "{}  Refreshing every {}s — Ctrl+C to exit{}",
                     C_DIM, watch_secs, C_RST);
      }
      std::cout << std::flush;
      std::this_thread::sleep_for(std::chrono::seconds(watch_secs));
    }
  } else {
    auto snap = take();
    if (!snap) return 1;
    if (json_mode) print_json(*snap);
    else {
      print_header(*snap);
      print_summary(*snap);
      print_table(*snap);
    }
  }
  return 0;
}
