// JNI surface for the native matcher.
//
// Results cross back as String[] of tab-joined records rather than as Java
// objects. Building a Hit object per finding would mean a FindClass/GetMethodID
// /NewObject round-trip per field; one NewStringUTF per finding is cheaper and
// keeps the boundary to two Java types (String, String[]). Kotlin splits them.
//
// The matcher lives behind an opaque jlong handle: the C++ object outlives any
// one call, so the 11k-row parse happens once, not per scan.

#include <jni.h>

#include "matcher.hpp"
#include "vercmp.hpp"

#include <memory>
#include <string>
#include <vector>

namespace {

dg::Matcher* from_handle(jlong h) { return reinterpret_cast<dg::Matcher*>(h); }

// Cached once in JNI_OnLoad. Before this, every call ran
// FindClass("java/lang/String") -- a class-table lookup plus a stack walk to
// find the caller's class loader -- and allocated a fresh String[] even to say
// "no hits". simpleperf put those two at ~19% of a no-hit call; see
// results/simpleperf/ and README "profiling the JNI boundary".
jclass g_string_class = nullptr;
jobjectArray g_empty = nullptr;  // shared String[0]; nothing mutates a zero-length array

// Copies a jstring's modified-UTF-8 bytes into a stack buffer.
// GetStringUTFChars would hand back a heap copy that ART mallocs and frees per
// call (the scudo allocate/deallocate frames in the "before" profile).
// GetStringUTFRegion writes into memory we own. Package names, versions and
// patch levels are ASCII, where modified UTF-8 and UTF-8 agree.
class Utf {
public:
    Utf(JNIEnv* env, jstring s) {
        if (s == nullptr) return;
        const jsize chars = env->GetStringLength(s);
        const jsize bytes = env->GetStringUTFLength(s);
        char* dst = stack_;
        if (static_cast<std::size_t>(bytes) >= sizeof(stack_)) {
            heap_.resize(static_cast<std::size_t>(bytes) + 1);
            dst = heap_.data();
        }
        env->GetStringUTFRegion(s, 0, chars, dst);
        dst[bytes] = '\0';
        view_ = std::string_view(dst, static_cast<std::size_t>(bytes));
    }
    Utf(const Utf&) = delete;
    Utf& operator=(const Utf&) = delete;
    std::string_view view() const { return view_; }

private:
    char stack_[256];
    std::string heap_;
    std::string_view view_;
};

std::string encode(const dg::Hit& h) {
    return h.cve + '\t' + h.target + '\t' + h.severity + '\t' + std::to_string(h.flags);
}

jobjectArray to_java(JNIEnv* env, const std::vector<std::string>& rows) {
    if (rows.empty()) return static_cast<jobjectArray>(env->NewLocalRef(g_empty));
    jobjectArray arr = env->NewObjectArray(static_cast<jsize>(rows.size()), g_string_class, nullptr);
    for (jsize i = 0; i < static_cast<jsize>(rows.size()); ++i) {
        jstring s = env->NewStringUTF(rows[static_cast<std::size_t>(i)].c_str());
        env->SetObjectArrayElement(arr, i, s);
        // Without this a 5k-finding result overflows the 512-entry local
        // reference table and aborts the process under CheckJNI.
        env->DeleteLocalRef(s);
    }
    return arr;
}

jobjectArray hits_to_java(JNIEnv* env, const std::vector<dg::Hit>& hits) {
    std::vector<std::string> rows;
    rows.reserve(hits.size());
    for (const auto& h : hits) rows.push_back(encode(h));
    return to_java(env, rows);
}

} // namespace

extern "C" {

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void*) {
    JNIEnv* env = nullptr;
    if (vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) != JNI_OK) return JNI_ERR;
    jclass local = env->FindClass("java/lang/String");
    if (local == nullptr) return JNI_ERR;
    g_string_class = static_cast<jclass>(env->NewGlobalRef(local));
    env->DeleteLocalRef(local);
    jobjectArray empty = env->NewObjectArray(0, g_string_class, nullptr);
    g_empty = static_cast<jobjectArray>(env->NewGlobalRef(empty));
    env->DeleteLocalRef(empty);
    return JNI_VERSION_1_6;
}

JNIEXPORT jlong JNICALL
Java_dev_droidguard_core_NativeMatcher_nativeLoad(JNIEnv* env, jclass, jbyteArray tsv) {
    const jsize n = env->GetArrayLength(tsv);
    std::string buf(static_cast<std::size_t>(n), '\0');
    env->GetByteArrayRegion(tsv, 0, n, reinterpret_cast<jbyte*>(buf.data()));

    auto m = std::make_unique<dg::Matcher>();
    std::string err;
    if (!m->load(buf, err)) {
        jclass ex = env->FindClass("java/lang/IllegalArgumentException");
        env->ThrowNew(ex, err.c_str());
        return 0;
    }
    return reinterpret_cast<jlong>(m.release());
}

JNIEXPORT void JNICALL
Java_dev_droidguard_core_NativeMatcher_nativeFree(JNIEnv*, jclass, jlong h) {
    delete from_handle(h);
}

JNIEXPORT jintArray JNICALL
Java_dev_droidguard_core_NativeMatcher_nativeCounts(JNIEnv* env, jclass, jlong h) {
    const dg::Matcher* m = from_handle(h);
    const jint v[4] = {static_cast<jint>(m->platform_rules()), static_cast<jint>(m->kernel_rules()),
                       static_cast<jint>(m->app_rules()), static_cast<jint>(m->aliases())};
    jintArray out = env->NewIntArray(4);
    env->SetIntArrayRegion(out, 0, 4, v);
    return out;
}

JNIEXPORT jobjectArray JNICALL
Java_dev_droidguard_core_NativeMatcher_nativeMatchPlatform(JNIEnv* env, jclass, jlong h,
                                                           jstring release, jstring spl) {
    Utf r(env, release), s(env, spl);
    return hits_to_java(env, from_handle(h)->match_platform(r.view(), s.view()));
}

JNIEXPORT jobjectArray JNICALL
Java_dev_droidguard_core_NativeMatcher_nativeMatchKernel(JNIEnv* env, jclass, jlong h,
                                                         jstring uname, jstring spl) {
    Utf u(env, uname), s(env, spl);
    return hits_to_java(env, from_handle(h)->match_kernel(u.view(), s.view()));
}

// One crossing per app. Kept alongside the batched form so the benchmark can
// show what call granularity costs.
JNIEXPORT jobjectArray JNICALL
Java_dev_droidguard_core_NativeMatcher_nativeMatchApp(JNIEnv* env, jclass, jlong h, jstring pkg,
                                                      jstring version) {
    Utf p(env, pkg), v(env, version);
    return hits_to_java(env, from_handle(h)->match_app(p.view(), v.view()));
}

// One crossing for the whole inventory. Each row is prefixed with the index of
// the app it belongs to.
JNIEXPORT jobjectArray JNICALL
Java_dev_droidguard_core_NativeMatcher_nativeMatchApps(JNIEnv* env, jclass, jlong h,
                                                       jobjectArray pkgs, jobjectArray versions) {
    const dg::Matcher* m = from_handle(h);
    const jsize n = env->GetArrayLength(pkgs);
    std::vector<std::string> rows;
    for (jsize i = 0; i < n; ++i) {
        auto* jp = static_cast<jstring>(env->GetObjectArrayElement(pkgs, i));
        auto* jv = static_cast<jstring>(env->GetObjectArrayElement(versions, i));
        {
            Utf p(env, jp), v(env, jv);
            for (const auto& hit : m->match_app(p.view(), v.view())) {
                rows.push_back(std::to_string(i) + '\t' + encode(hit));
            }
        }
        env->DeleteLocalRef(jp);
        env->DeleteLocalRef(jv);
    }
    return to_java(env, rows);
}

JNIEXPORT jint JNICALL
Java_dev_droidguard_core_NativeMatcher_nativeCompare(JNIEnv* env, jclass, jstring a, jstring b) {
    Utf x(env, a), y(env, b);
    return dg::version_compare(x.view(), y.view());
}

// The floor: a call that does nothing, for subtracting crossing cost out of the
// matcher timings.
JNIEXPORT jint JNICALL
Java_dev_droidguard_core_NativeMatcher_nativeNoop(JNIEnv*, jclass, jlong h) {
    return static_cast<jint>(h & 1);
}

} // extern "C"
