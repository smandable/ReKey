import SwiftUI
import Model
import ResetRouter

/// One pill badge: an optional SF Symbol plus text in a tinted capsule. The
/// single source of the badge styling used across findings, sources, and reset.
struct PillBadge: View {
    var icon: String? = nil
    let text: String
    let color: Color

    var body: some View {
        HStack(spacing: 4) {
            if let icon { Image(systemName: icon) }
            Text(text)
        }
        .font(.caption2.weight(.semibold))
        .padding(.horizontal, 7)
        .padding(.vertical, 3)
        .background(color.opacity(0.18), in: Capsule())
        .foregroundStyle(color)
    }
}

/// The browser/source badge.
struct BrowserSourcePill: View {
    let source: BrowserSource
    var body: some View {
        PillBadge(text: source.displayName, color: source.badgeColor)
    }
}

/// Presentation for a finding kind: label, color, icon. Pure mapping, no state.
enum FindingStyle {
    static func label(_ kind: FindingKind) -> String {
        switch kind {
        case .compromisedAndReused: return "Compromised + Reused"
        case .compromised: return "Compromised"
        case .reusedAcrossSites: return "Reused"
        case .duplicatedWithinSite: return "Duplicate"
        }
    }

    static func color(_ kind: FindingKind) -> Color {
        switch kind {
        case .compromisedAndReused, .compromised: return .red
        case .reusedAcrossSites: return .orange
        case .duplicatedWithinSite: return .yellow
        }
    }

    static func icon(_ kind: FindingKind) -> String {
        switch kind {
        case .compromisedAndReused, .compromised: return "exclamationmark.octagon.fill"
        case .reusedAcrossSites: return "arrow.triangle.2.circlepath"
        case .duplicatedWithinSite: return "doc.on.doc"
        }
    }
}

/// A small pill badge for a finding.
struct FindingBadge: View {
    let kind: FindingKind
    var breachCount: Int? = nil

    var body: some View {
        PillBadge(icon: FindingStyle.icon(kind), text: text, color: FindingStyle.color(kind))
    }

    private var text: String {
        if let breachCount, kind == .compromised || kind == .compromisedAndReused {
            return "\(FindingStyle.label(kind)) · \(breachCount.formatted()) breaches"
        }
        return FindingStyle.label(kind)
    }
}

/// How a credential's change-password URL was resolved, for display in the fix
/// queue. The `.wellKnown` case is the gold standard — the site exposes the W3C
/// `.well-known/change-password` URL that Safari and Chrome use too.
struct ResetSourceBadge: View {
    let source: ResetSource

    var body: some View {
        PillBadge(icon: icon, text: label, color: color)
    }

    private var icon: String {
        switch source {
        case .wellKnown: return "checkmark.seal.fill"
        case .fallbackMap: return "list.bullet.rectangle.fill"
        case .siteRoot: return "questionmark.circle"
        }
    }

    private var label: String {
        switch source {
        case .wellKnown: return "Supports .well-known/change-password"
        case .fallbackMap: return "Known change page"
        case .siteRoot: return "No change page found"
        }
    }

    private var color: Color {
        switch source {
        case .wellKnown: return .green
        case .fallbackMap: return .blue
        case .siteRoot: return .orange
        }
    }

    /// Longer explanation shown under the badge.
    static func explanation(_ source: ResetSource) -> String {
        switch source {
        case .wellKnown:
            return "This site exposes the standard change-password URL — the same mechanism Safari and Chrome use."
        case .fallbackMap:
            return "Resolved from Rekey's curated list of change-password pages."
        case .siteRoot:
            return "Rekey couldn't find a change-password page. It'll open the site root — look in account or security settings."
        }
    }
}

extension Model.BrowserSource {
    var badgeColor: Color {
        switch self {
        case .chrome: return .blue
        case .arc: return .purple
        case .brave: return .orange
        case .edge: return .teal
        case .opera: return .red
        case .vivaldi: return .pink
        case .chromium: return .indigo
        case .firefox: return .orange
        case .applePasswords: return .gray
        case .unknown: return .secondary
        }
    }
}
