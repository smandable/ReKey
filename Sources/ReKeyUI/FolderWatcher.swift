import Foundation

/// Watches a directory and calls `onChange` (on the main actor) whenever its
/// contents change.
///
/// Two mechanisms run together:
///  - A kqueue/vnode `DispatchSource`, which fires *instantly* — but only
///    reliably for folders on the boot volume.
///  - A periodic poll timer, the dependable fallback for folders on **external
///    and network volumes** (e.g. `/Volumes/…`), where vnode events frequently
///    aren't delivered at all. Polling is cheap (one directory listing) and the
///    downstream scan is idempotent (already-seen exports are skipped by
///    signature), so the extra ticks are harmless.
@MainActor
final class FolderWatcher {
    private var source: DispatchSourceFileSystemObject?
    private var descriptor: Int32 = -1
    private var pollTimer: DispatchSourceTimer?
    private(set) var url: URL?
    var onChange: (@MainActor () -> Void)?

    /// How often the poll fallback re-scans. Small enough to feel prompt,
    /// large enough to be negligible. Injectable for tests.
    let pollInterval: TimeInterval

    init(pollInterval: TimeInterval = 3) {
        self.pollInterval = pollInterval
    }

    func start(url: URL) {
        stop()
        self.url = url

        // Instant path: kqueue vnode events. Best-effort — if the open fails or
        // the volume never delivers events, the poll timer below still covers it.
        let fd = open(url.path, O_EVTONLY)
        if fd >= 0 {
            descriptor = fd
            let src = DispatchSource.makeFileSystemObjectSource(
                fileDescriptor: fd,
                eventMask: [.write, .extend, .rename, .delete, .link],
                queue: .main
            )
            src.setEventHandler { [weak self] in
                // The source uses the main queue, so we're already on the main actor.
                MainActor.assumeIsolated { self?.onChange?() }
            }
            // Capture the fd by value so closing doesn't depend on `self`.
            src.setCancelHandler { close(fd) }
            source = src
            src.resume()
        }

        // Reliable fallback: poll on a timer, so external/network-volume folders
        // (which vnode events miss) still auto-import.
        let timer = DispatchSource.makeTimerSource(queue: .main)
        timer.schedule(deadline: .now() + pollInterval, repeating: pollInterval)
        timer.setEventHandler { [weak self] in
            MainActor.assumeIsolated { self?.onChange?() }
        }
        pollTimer = timer
        timer.resume()
    }

    func stop() {
        source?.cancel()     // the cancel handler closes the descriptor
        source = nil
        descriptor = -1
        pollTimer?.cancel()
        pollTimer = nil
        url = nil
    }

    deinit {
        source?.cancel()
        pollTimer?.cancel()
    }
}
