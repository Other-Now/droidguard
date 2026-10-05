#include "matcher.hpp"

#include "vercmp.hpp"

#include <unordered_set>

namespace dg {

namespace {

constexpr std::string_view kHeader =
    "kind\tcve\ttarget\trelease\tfixed_spl\tstart_incl\tstart_excl\tend_incl\tend_excl\tseverity";

// Splits one line on tabs without allocating per field until the caller copies.
std::vector<std::string_view> split_tabs(std::string_view line) {
    std::vector<std::string_view> out;
    std::size_t start = 0;
    while (true) {
        const auto tab = line.find('\t', start);
        if (tab == std::string_view::npos) {
            out.push_back(line.substr(start));
            return out;
        }
        out.push_back(line.substr(start, tab - start));
        start = tab + 1;
    }
}

bool has_range(const Rule& r) {
    return !r.start_incl.empty() || !r.start_excl.empty() || !r.end_incl.empty() ||
           !r.end_excl.empty();
}

bool in_range(std::string_view v, const Rule& r) {
    return version_in_range(v, r.start_incl, r.start_excl, r.end_incl, r.end_excl);
}

} // namespace

bool valid_spl(std::string_view s) {
    if (s.size() != 10 || s[4] != '-' || s[7] != '-') return false;
    for (std::size_t i : {0, 1, 2, 3, 5, 6, 8, 9}) {
        if (s[i] < '0' || s[i] > '9') return false;
    }
    return true;
}

std::string kernel_upstream(std::string_view u) {
    const auto cut = u.find_first_of("-+");
    return std::string(cut == std::string_view::npos ? u : u.substr(0, cut));
}

bool Matcher::load(std::string_view tsv, std::string& error) {
    platform_.clear();
    kernel_.clear();
    apps_.clear();
    alias_.clear();

    std::size_t pos = 0;
    bool header_seen = false;
    std::size_t lineno = 0;
    while (pos < tsv.size()) {
        auto nl = tsv.find('\n', pos);
        if (nl == std::string_view::npos) nl = tsv.size();
        std::string_view line = tsv.substr(pos, nl - pos);
        pos = nl + 1;
        ++lineno;
        if (!line.empty() && line.back() == '\r') line.remove_suffix(1);
        if (line.empty() || line[0] == '#') continue;

        if (!header_seen) {
            if (line != kHeader) {
                error = "unexpected rules header";
                return false;
            }
            header_seen = true;
            continue;
        }

        const auto c = split_tabs(line);
        if (c.size() != 10) {
            error = "rules line " + std::to_string(lineno) + ": expected 10 columns";
            return false;
        }
        const std::string_view kind = c[0];
        if (kind == "alias") {
            alias_.emplace(std::string(c[2]), std::string(c[3]));
            continue;
        }

        Rule r{std::string(c[1]), std::string(c[2]), std::string(c[3]), std::string(c[4]),
               std::string(c[5]), std::string(c[6]), std::string(c[7]), std::string(c[8]),
               std::string(c[9])};
        if (kind == "platform") {
            platform_.push_back(std::move(r));
        } else if (kind == "kernel") {
            kernel_.push_back(std::move(r));
        } else if (kind == "app") {
            apps_[r.target].push_back(std::move(r));
        } else {
            error = "rules line " + std::to_string(lineno) + ": unknown kind";
            return false;
        }
    }
    if (!header_seen) {
        error = "rules are empty";
        return false;
    }
    return true;
}

std::size_t Matcher::app_rules() const {
    std::size_t n = 0;
    for (const auto& [_, v] : apps_) n += v.size();
    return n;
}

std::vector<Hit> Matcher::match_platform(std::string_view release, std::string_view spl) const {
    std::vector<Hit> out;
    if (!valid_spl(spl)) return out;
    std::unordered_set<std::string> seen;
    for (const Rule& r : platform_) {
        // Exact string equality, on purpose: "12" must not match "12L" (a
        // different release with its own fix SPLs), which is the mistake a
        // substring test makes.
        if (r.release != release) continue;
        if (!(spl < std::string_view(r.fixed_spl))) continue;
        if (!seen.insert(r.cve).second) continue;  // one CVE, several components
        out.push_back({r.cve, r.target, r.severity, kSplUnpatched});
    }
    return out;
}

std::vector<Hit> Matcher::match_kernel(std::string_view uname, std::string_view spl) const {
    std::vector<Hit> out;
    const std::string v = kernel_upstream(uname);
    const bool spl_ok = valid_spl(spl);

    // Rules for one CVE are contiguous (one row per NVD range), so fold them as
    // we go rather than building a map. The same CVE can still recur in a
    // second bulletin entry, hence `seen`.
    std::unordered_set<std::string> seen;
    std::size_t i = 0;
    while (i < kernel_.size()) {
        const Rule& first = kernel_[i];
        std::uint32_t flags = 0;
        bool any_range = false;
        std::size_t j = i;
        for (; j < kernel_.size() && kernel_[j].cve == first.cve; ++j) {
            const Rule& r = kernel_[j];
            if (!has_range(r)) continue;
            any_range = true;
            if (!v.empty() && in_range(v, r)) flags |= kVersionInRange;
        }
        if (!any_range) flags |= kVersionUnknown;
        if (spl_ok && spl < std::string_view(first.fixed_spl)) flags |= kSplUnpatched;
        if ((flags & (kSplUnpatched | kVersionInRange)) && seen.insert(first.cve).second) {
            out.push_back({first.cve, first.target, first.severity, flags});
        }
        i = j;
    }
    return out;
}

std::vector<Hit> Matcher::match_app(std::string_view package, std::string_view version) const {
    std::vector<Hit> out;
    if (version.empty()) return out;
    const auto a = alias_.find(std::string(package));
    if (a == alias_.end()) return out;
    const auto it = apps_.find(a->second);
    if (it == apps_.end()) return out;

    std::unordered_set<std::string> seen;
    for (const Rule& r : it->second) {
        if (!in_range(version, r)) continue;
        if (!seen.insert(r.cve).second) continue;
        out.push_back({r.cve, r.target, r.severity, 0});
    }
    return out;
}

} // namespace dg
