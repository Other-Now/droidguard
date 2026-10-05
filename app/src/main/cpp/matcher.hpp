#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace dg {

// One row of assets/rules.tsv (built by tools/build_rules.py).
struct Rule {
    std::string cve;
    std::string target;     // AOSP project, "linux_kernel", or CPE "vendor:product"
    std::string release;    // platform rules only: "12L", "13", ...
    std::string fixed_spl;  // platform/kernel: first patch level that has the fix
    std::string start_incl, start_excl, end_incl, end_excl;
    std::string severity;
};

// Kernel findings carry two independent signals, because on Android they
// disagree often enough to matter (see README, "kernel: version vs patch level").
enum KernelFlags : std::uint32_t {
    kSplUnpatched = 1u << 0,   // device patch level is older than the bulletin fix
    kVersionInRange = 1u << 1, // upstream kernel version is inside an NVD range
    kVersionUnknown = 1u << 2, // NVD has no range for this CVE
};

// The kernel verdict needs both signals. Patch level alone over-reports a device
// whose kernel is already past the upstream fix (an old SPL on a new LTS);
// version alone over-reports every fix a vendor backported without bumping the
// version. Unknown version (no NVD range) defers to the patch level.
inline bool kernel_vulnerable(std::uint32_t f) {
    return (f & kSplUnpatched) && (f & (kVersionInRange | kVersionUnknown));
}

struct Hit {
    std::string cve;
    std::string target;
    std::string severity;
    std::uint32_t flags = 0;
};

class Matcher {
public:
    // Parses the whole TSV. The header is checked, not skipped: a reordered
    // column would otherwise shift every field and give a confidently wrong
    // matcher (same rule as nano-sensor's CVE index loader).
    bool load(std::string_view tsv, std::string& error);

    // Platform CVEs affecting `release` ("14", "12L") at patch level `spl`
    // ("2024-03-01"). Affected iff the release is listed and spl < fixed_spl.
    std::vector<Hit> match_platform(std::string_view release, std::string_view spl) const;

    // Every bulletin kernel CVE for which EITHER signal fires, so the report can
    // show the disagreements. Use kernel_vulnerable() for the verdict;
    // kVersionInRange without kSplUnpatched means the fix was backported.
    std::vector<Hit> match_kernel(std::string_view uname_release, std::string_view spl) const;

    // CVEs affecting an installed app at `version_name`. Empty when the package
    // has no alias (most apps -- that is the common, fast path).
    std::vector<Hit> match_app(std::string_view package, std::string_view version_name) const;

    std::size_t platform_rules() const { return platform_.size(); }
    std::size_t kernel_rules() const { return kernel_.size(); }
    std::size_t app_rules() const;
    std::size_t aliases() const { return alias_.size(); }

private:
    std::vector<Rule> platform_;
    std::vector<Rule> kernel_;
    std::unordered_map<std::string, std::vector<Rule>> apps_;  // by CPE product
    std::unordered_map<std::string, std::string> alias_;       // package -> CPE product
};

// "5.15.137-android14-11-g2f1c" -> "5.15.137". Everything after the first '-' or
// '+' is the vendor's build identity, not an upstream version. (vercmp's
// version_upstream_part strips from the LAST '-', which is right for Debian
// revisions and wrong here.)
std::string kernel_upstream(std::string_view uname_release);

// Patch levels are ISO dates, so "YYYY-MM-DD" compares correctly as a string --
// but only when both sides are well formed. A malformed device value must never
// read as "older than everything" and flood the report.
bool valid_spl(std::string_view spl);

} // namespace dg
