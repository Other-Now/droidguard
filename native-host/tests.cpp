// Unit tests for the native core. Tiny harness on purpose (same as nano-sensor):
// no third-party test framework to vendor into an NDK build.
#include "common.hpp"
#include "matcher.hpp"
#include "vercmp.hpp"

#include <cstdio>
#include <functional>
#include <string>
#include <vector>

namespace {

int g_failed = 0;
int g_checks = 0;

#define CHECK(cond)                                                              \
    do {                                                                         \
        ++g_checks;                                                              \
        if (!(cond)) {                                                           \
            ++g_failed;                                                          \
            std::printf("  FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);       \
        }                                                                        \
    } while (0)

struct Test {
    const char* name;
    std::function<void()> fn;
};
std::vector<Test>& registry() {
    static std::vector<Test> t;
    return t;
}
struct Reg {
    Reg(const char* n, std::function<void()> f) { registry().push_back({n, std::move(f)}); }
};
#define TEST(name)                                       \
    void name();                                         \
    Reg reg_##name(#name, name);                         \
    void name()

const char* kHeader =
    "kind\tcve\ttarget\trelease\tfixed_spl\tstart_incl\tstart_excl\tend_incl\tend_excl\tseverity\n";

dg::Matcher load_or_die(const std::string& tsv) {
    dg::Matcher m;
    std::string err;
    if (!m.load(tsv, err)) std::printf("  load error: %s\n", err.c_str());
    return m;
}

bool has(const std::vector<dg::Hit>& hits, const std::string& cve) {
    for (const auto& h : hits)
        if (h.cve == cve) return true;
    return false;
}

std::string g_rules_path;

} // namespace

TEST(vercmp_numeric_not_lexical) {
    CHECK(dg::version_compare("117.0.5938.60", "117.0.5938.132") < 0);
    CHECK(dg::version_compare("99.0", "117.0") < 0);
    CHECK(dg::version_compare("4.14.99", "4.14.149") < 0);
    CHECK(dg::version_compare("1.10", "1.9") > 0);
}

TEST(vercmp_equal_and_trailing) {
    CHECK(dg::version_compare("85.0", "85.0") == 0);
    CHECK(dg::version_compare("85.0.1", "85.0") > 0);
    CHECK(dg::version_compare("007", "7") == 0);
    CHECK(dg::version_compare("1.0rc1", "1.0") < 0);
}

TEST(spl_validation) {
    CHECK(dg::valid_spl("2024-03-05"));
    CHECK(!dg::valid_spl(""));
    CHECK(!dg::valid_spl("2024-3-5"));
    CHECK(!dg::valid_spl("unknown"));
    CHECK(!dg::valid_spl("2024/03/05"));
}

TEST(kernel_upstream_strips_vendor_suffix) {
    CHECK(dg::kernel_upstream("5.15.137-android14-11-g2f1c") == "5.15.137");
    CHECK(dg::kernel_upstream("6.1.75+") == "6.1.75");
    CHECK(dg::kernel_upstream("4.19.75") == "4.19.75");
    CHECK(dg::kernel_upstream("") == "");
}

TEST(load_rejects_bad_header) {
    dg::Matcher m;
    std::string err;
    CHECK(!m.load("cve\tkind\n", err));
    CHECK(!err.empty());
    CHECK(!m.load("", err));
}

TEST(load_rejects_wrong_column_count) {
    dg::Matcher m;
    std::string err;
    CHECK(!m.load(std::string(kHeader) + "platform\tCVE-1\tx\t13\n", err));
}

TEST(load_rejects_unknown_kind) {
    dg::Matcher m;
    std::string err;
    CHECK(!m.load(std::string(kHeader) + "bogus\tCVE-1\tx\t\t\t\t\t\t\t\n", err));
}

TEST(platform_release_is_exact) {
    auto m = load_or_die(std::string(kHeader) +
                         "platform\tCVE-A\tp\t12L\t2022-09-01\t\t\t\t\tHigh\n");
    CHECK(has(m.match_platform("12L", "2022-08-01"), "CVE-A"));
    CHECK(!has(m.match_platform("12", "2022-08-01"), "CVE-A"));
    CHECK(!has(m.match_platform("1", "2022-08-01"), "CVE-A"));
}

TEST(platform_spl_boundary) {
    auto m = load_or_die(std::string(kHeader) +
                         "platform\tCVE-A\tp\t14\t2024-06-05\t\t\t\t\tHigh\n");
    CHECK(has(m.match_platform("14", "2024-06-01"), "CVE-A"));
    CHECK(!has(m.match_platform("14", "2024-06-05"), "CVE-A"));
    CHECK(!has(m.match_platform("14", "2024-07-01"), "CVE-A"));
    CHECK(!has(m.match_platform("14", ""), "CVE-A"));
}

TEST(platform_reissued_fix_uses_latest) {
    auto m = load_or_die(std::string(kHeader) +
                         "platform\tCVE-A\tp\t13\t2023-06-01\t\t\t\t\tHigh\n"
                         "platform\tCVE-A\tp\t13\t2024-08-01\t\t\t\t\tHigh\n");
    auto hits = m.match_platform("13", "2023-07-01");
    CHECK(hits.size() == 1);  // and reported once, not twice
    CHECK(!has(m.match_platform("13", "2024-08-01"), "CVE-A"));
}

TEST(platform_dedupes_components) {
    auto m = load_or_die(std::string(kHeader) +
                         "platform\tCVE-A\tp1\t13\t2023-06-01\t\t\t\t\tHigh\n"
                         "platform\tCVE-A\tp2\t13\t2023-06-01\t\t\t\t\tHigh\n");
    CHECK(m.match_platform("13", "2023-01-01").size() == 1);
}

TEST(kernel_flags) {
    auto m = load_or_die(std::string(kHeader) +
                         "kernel\tCVE-K\tlinux_kernel\t\t2020-08-05\t4.15\t\t\t4.19.79\tHigh\n"
                         "kernel\tCVE-K\tlinux_kernel\t\t2020-08-05\t4.20\t\t\t5.3.6\tHigh\n"
                         "kernel\tCVE-N\tlinux_kernel\t\t2020-09-05\t\t\t\t\tHigh\n");
    auto hits = m.match_kernel("4.19.75-android", "2020-07-05");
    CHECK(hits.size() == 2);
    for (const auto& h : hits) {
        if (h.cve == "CVE-K") {
            CHECK(h.flags == (dg::kSplUnpatched | dg::kVersionInRange));
            CHECK(dg::kernel_vulnerable(h.flags));
        } else {
            CHECK(h.flags == (dg::kSplUnpatched | dg::kVersionUnknown));
            CHECK(dg::kernel_vulnerable(h.flags));
        }
    }
    // Backport: in range, patch level current. Reported with the flag, not vulnerable.
    for (const auto& h : m.match_kernel("4.19.75", "2020-09-05")) {
        CHECK(h.cve == "CVE-K");
        CHECK(h.flags == dg::kVersionInRange);
        CHECK(!dg::kernel_vulnerable(h.flags));
    }
    // Old patch level but kernel already past the upstream fix.
    for (const auto& h : m.match_kernel("4.19.100", "2020-07-05")) {
        if (h.cve == "CVE-K") CHECK(!dg::kernel_vulnerable(h.flags));
    }
}

TEST(app_alias_and_ranges) {
    auto m = load_or_die(std::string(kHeader) +
                         "app\tCVE-C\tgoogle:chrome\t\t\t\t\t\t117.0.5938.132\tHigh\n"
                         "app\tCVE-E\tgoogle:chrome\t\t\t100.0\t\t100.0\t\tHigh\n"
                         "alias\t-\tcom.android.chrome\tgoogle:chrome\t\t\t\t\t\t\n");
    CHECK(m.aliases() == 1);
    CHECK(has(m.match_app("com.android.chrome", "117.0.5938.60"), "CVE-C"));
    CHECK(!has(m.match_app("com.android.chrome", "117.0.5938.132"), "CVE-C"));
    CHECK(has(m.match_app("com.android.chrome", "100.0"), "CVE-E"));
    CHECK(!has(m.match_app("com.android.chrome", "100.0.1"), "CVE-E"));
    CHECK(m.match_app("com.other", "1.0").empty());
    CHECK(m.match_app("com.android.chrome", "").empty());
}

TEST(real_rules_load) {
    if (g_rules_path.empty()) return;
    dg::Matcher m;
    std::string err;
    CHECK(m.load(read_file(g_rules_path), err));
    CHECK(m.platform_rules() > 4000);
    CHECK(m.kernel_rules() > 500);
    CHECK(m.app_rules() > 5000);
    CHECK(m.aliases() == 6);
    // A fully patched current device has no platform findings for old CVEs.
    CHECK(m.match_platform("14", "2099-01-01").empty());
}

int main(int argc, char** argv) {
    if (argc > 1) g_rules_path = argv[1];
    for (const auto& t : registry()) {
        const int before = g_failed;
        t.fn();
        std::printf("%s %s\n", g_failed == before ? "ok  " : "FAIL", t.name);
    }
    std::printf("%zu tests, %d checks, %d failed\n", registry().size(), g_checks, g_failed);
    return g_failed == 0 ? 0 : 1;
}
