// Print the CGWindowID of ReKey's main on-screen window, so screenshots.sh can
// grab it with `screencapture -l` instead of waiting for a human to click.
// Swift rather than Python because PyObjC isn't part of a stock macOS install,
// but the Swift toolchain is already required to build ReKey at all.
//
//   swift Scripts/window-id.swift     → prints the id, or exits 1 if not found.
import CoreGraphics
import Foundation

let opts: CGWindowListOption = [.optionOnScreenOnly, .excludeDesktopElements]
guard let list = CGWindowListCopyWindowInfo(opts, kCGNullWindowID) as? [[String: Any]] else {
    FileHandle.standardError.write(Data("window list unavailable\n".utf8))
    exit(1)
}
for w in list {
    guard let owner = w[kCGWindowOwnerName as String] as? String, owner == "ReKey",
          let bounds = w[kCGWindowBounds as String] as? [String: Any],
          let height = bounds["Height"] as? Double, height > 200,   // skip 0x0 helper windows
          let number = w[kCGWindowNumber as String] as? Int else { continue }
    print(number)
    exit(0)
}
FileHandle.standardError.write(Data("no on-screen ReKey window\n".utf8))
exit(1)
