import SwiftUI
import Model

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
        let color = FindingStyle.color(kind)
        HStack(spacing: 4) {
            Image(systemName: FindingStyle.icon(kind))
            Text(text)
        }
        .font(.caption2.weight(.semibold))
        .padding(.horizontal, 7)
        .padding(.vertical, 3)
        .background(color.opacity(0.18), in: Capsule())
        .foregroundStyle(color)
    }

    private var text: String {
        if let breachCount, kind == .compromised || kind == .compromisedAndReused {
            return "\(FindingStyle.label(kind)) · \(breachCount.formatted()) breaches"
        }
        return FindingStyle.label(kind)
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
