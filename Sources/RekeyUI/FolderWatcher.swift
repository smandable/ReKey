import Foundation

/// Watches a directory and calls `onChange` (on the main actor) whenever its
/// contents change. Thin wrapper over a DispatchSource file-system-object source.
@MainActor
final class FolderWatcher {
    private var source: DispatchSourceFileSystemObject?
    private var descriptor: Int32 = -1
    private(set) var url: URL?
    var onChange: (@MainActor () -> Void)?

    func start(url: URL) {
        stop()
        let fd = open(url.path, O_EVTONLY)
        guard fd >= 0 else { return }
        descriptor = fd
        self.url = url

        let src = DispatchSource.makeFileSystemObjectSource(
            fileDescriptor: fd,
            eventMask: [.write, .extend, .rename, .delete],
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

    func stop() {
        source?.cancel()     // the cancel handler closes the descriptor
        source = nil
        descriptor = -1
        url = nil
    }

    deinit {
        source?.cancel()
    }
}
