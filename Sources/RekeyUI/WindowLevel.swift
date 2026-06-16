import SwiftUI
import AppKit

/// Pins the hosting window's level so Rekey can float above the browser window it
/// spawns for a change page. Sandbox-safe: it only ever touches Rekey's *own*
/// window — never another app's — which is the most a sandboxed app can do about
/// window placement. Attach as a `.background(...)` of the root view.
struct WindowLevelModifier: NSViewRepresentable {
    /// When true, the window floats above normal windows (including the browser).
    var keepOnTop: Bool

    func makeNSView(context: Context) -> NSView {
        let view = NSView()
        apply(via: view)
        return view
    }

    func updateNSView(_ nsView: NSView, context: Context) {
        apply(via: nsView)
    }

    /// `view.window` is nil until the view joins the hierarchy, so defer a tick.
    private func apply(via view: NSView) {
        let keepOnTop = keepOnTop
        DispatchQueue.main.async {
            guard let window = view.window else { return }
            let level: NSWindow.Level = keepOnTop ? .floating : .normal
            if window.level != level { window.level = level }
        }
    }
}
