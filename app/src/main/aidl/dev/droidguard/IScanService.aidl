package dev.droidguard;

// Scan results over Binder. The service runs in its own process (":scanner"),
// so every call here is a real cross-process transaction, not an in-process
// shortcut.
interface IScanService {
    // Runs a full scan and returns the report as JSON. Blocking: call it off the
    // main thread.
    String runScan();

    // Finding count of the most recent scan, or -1 if none has run.
    int lastFindingCount();

    // Rule counts loaded by the native core: platform, kernel, app, aliases.
    int[] ruleCounts();

    // Pid of the service process, so tests can prove the call crossed processes.
    int servicePid();
}
