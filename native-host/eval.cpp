// Scores the matcher against data/labels.tsv, next to a naive baseline that
// makes the three mistakes this matcher exists to avoid:
//   * versions compared as strings ("117.0.5938.60" > "117.0.5938.132"),
//   * releases matched by prefix ("12" hits a rule for "12L"),
//   * kernel judged by one signal (version only, ignoring the patch level),
//     and patch levels compared without validating them first.
//
//   dg_eval rules.tsv labels.tsv [--json] [--min-f1 X]
#include "common.hpp"
#include "matcher.hpp"

#include <cstdio>
#include <cstdlib>
#include <map>
#include <string>
#include <vector>

namespace {

struct Row {
    std::vector<std::string> c;
};

struct Score {
    int tp = 0, fp = 0, fn = 0, tn = 0;
    void add(bool predicted, bool expected) {
        if (predicted && expected) ++tp;
        else if (predicted) ++fp;
        else if (expected) ++fn;
        else ++tn;
    }
    double precision() const { return tp + fp ? double(tp) / (tp + fp) : 1.0; }
    double recall() const { return tp + fn ? double(tp) / (tp + fn) : 1.0; }
    double f1() const {
        const double p = precision(), r = recall();
        return p + r ? 2 * p * r / (p + r) : 0.0;
    }
};

bool lex_in_range(const std::string& v, const std::vector<std::string>& r) {
    // r = start_incl, start_excl, end_incl, end_excl
    if (!r[0].empty() && v < r[0]) return false;
    if (!r[1].empty() && v <= r[1]) return false;
    if (!r[2].empty() && v > r[2]) return false;
    if (!r[3].empty() && v >= r[3]) return false;
    return true;
}

// The baseline reads the same rules, just naively.
struct Naive {
    std::vector<std::vector<std::string>> rows;
    std::map<std::string, std::string> alias;

    explicit Naive(const std::string& tsv) {
        bool first = true;
        for (const auto& line : split(tsv, '\n')) {
            if (line.empty()) continue;
            if (first) { first = false; continue; }
            auto c = split(line, '\t');
            if (c.size() != 10) continue;
            if (c[0] == "alias") alias[c[2]] = c[3];
            else rows.push_back(c);
        }
    }

    bool hit(const std::string& kind, const std::string& a, const std::string& b,
             const std::string& cve) const {
        for (const auto& r : rows) {
            if (r[0] != kind || r[1] != cve) continue;
            std::vector<std::string> range(r.begin() + 5, r.begin() + 9);
            if (kind == "platform") {
                if (r[3].rfind(a, 0) == 0 && b < r[4]) return true;
            } else if (kind == "kernel") {
                const bool ranged = !(range[0] + range[1] + range[2] + range[3]).empty();
                const std::string v = a.substr(0, a.find_first_of("-+"));
                if (ranged && lex_in_range(v, range)) return true;
            } else if (kind == "app") {
                auto it = alias.find(a);
                if (it == alias.end() || it->second != r[2] || b.empty()) continue;
                if (lex_in_range(b, range)) return true;
            }
        }
        return false;
    }
};

bool matcher_hit(const dg::Matcher& m, const std::string& kind, const std::string& a,
                 const std::string& b, const std::string& cve) {
    if (kind == "platform") {
        for (const auto& h : m.match_platform(a, b))
            if (h.cve == cve) return true;
    } else if (kind == "kernel") {
        for (const auto& h : m.match_kernel(a, b))
            if (h.cve == cve && dg::kernel_vulnerable(h.flags)) return true;
    } else if (kind == "app") {
        for (const auto& h : m.match_app(a, b))
            if (h.cve == cve) return true;
    }
    return false;
}

} // namespace

int main(int argc, char** argv) {
    if (argc < 3) {
        std::fprintf(stderr, "usage: dg_eval rules.tsv labels.tsv [--json] [--min-f1 X]\n");
        return 2;
    }
    bool json = false;
    double min_f1 = -1;
    for (int i = 3; i < argc; ++i) {
        const std::string a = argv[i];
        if (a == "--json") json = true;
        else if (a == "--min-f1" && i + 1 < argc) min_f1 = std::atof(argv[++i]);
    }

    const std::string tsv = read_file(argv[1]);
    dg::Matcher m;
    std::string err;
    if (!m.load(tsv, err)) {
        std::fprintf(stderr, "load: %s\n", err.c_str());
        return 2;
    }
    Naive naive(tsv);

    std::map<std::string, Score> ours, base;
    Score ours_all, base_all;
    std::vector<std::string> misses;
    int n = 0;
    bool header = true;
    for (const auto& line : split(read_file(argv[2]), '\n')) {
        if (line.empty() || line[0] == '#') continue;
        if (header) { header = false; continue; }
        auto c = split(line, '\t');
        if (c.size() < 5) continue;
        const bool expected = c[4] == "1";
        const bool p = matcher_hit(m, c[0], c[1], c[2], c[3]);
        const bool q = naive.hit(c[0], c[1], c[2], c[3]);
        ours[c[0]].add(p, expected);
        base[c[0]].add(q, expected);
        ours_all.add(p, expected);
        base_all.add(q, expected);
        if (p != expected) misses.push_back(line);
        ++n;
    }

    if (json) {
        std::printf("{\"cases\":%d,\"positives\":%d", n, ours_all.tp + ours_all.fn);
        auto dump = [](const char* name, const std::map<std::string, Score>& s, const Score& all) {
            std::printf(",\"%s\":{", name);
            for (const auto& [k, v] : s)
                std::printf("\"%s\":{\"precision\":%.3f,\"recall\":%.3f,\"tp\":%d,\"fp\":%d,\"fn\":%d,\"tn\":%d},",
                            k.c_str(), v.precision(), v.recall(), v.tp, v.fp, v.fn, v.tn);
            std::printf("\"all\":{\"precision\":%.3f,\"recall\":%.3f,\"tp\":%d,\"fp\":%d,\"fn\":%d,\"tn\":%d}}",
                        all.precision(), all.recall(), all.tp, all.fp, all.fn, all.tn);
        };
        dump("matcher", ours, ours_all);
        dump("naive", base, base_all);
        std::printf("}\n");
    } else {
        std::printf("%d labelled cases (%d positive)\n\n", n, ours_all.tp + ours_all.fn);
        std::printf("%-9s %22s %22s\n", "kind", "matcher  P / R", "naive  P / R");
        for (const auto& [k, v] : ours) {
            const Score& b = base[k];
            std::printf("%-9s %10.1f%% / %5.1f%% %10.1f%% / %5.1f%%   (naive fp=%d fn=%d)\n", k.c_str(),
                        100 * v.precision(), 100 * v.recall(), 100 * b.precision(), 100 * b.recall(),
                        b.fp, b.fn);
        }
        std::printf("%-9s %10.1f%% / %5.1f%% %10.1f%% / %5.1f%%\n", "all", 100 * ours_all.precision(),
                    100 * ours_all.recall(), 100 * base_all.precision(), 100 * base_all.recall());
        for (const auto& l : misses) std::printf("MISS %s\n", l.c_str());
    }
    if (min_f1 >= 0 && ours_all.f1() + 1e-9 < min_f1) return 1;
    return 0;
}
