import Foundation

/// The category of a finding. A credential can be both reused and compromised;
/// `compromisedAndReused` carries that combined case so the UI can rank it
/// highest.
public enum FindingKind: String, Sendable, Equatable, Codable {
    /// Same password value on two or more *different* registrable domains.
    /// The high-signal finding and the primary reason this app exists.
    case reusedAcrossSites
    /// Same password on the *same* registrable domain under different
    /// usernames. Lower signal, sometimes legitimate; de-emphasized.
    case duplicatedWithinSite
    /// Appears in a known breach corpus (HIBP).
    case compromised
    /// Both compromised and reused across sites.
    case compromisedAndReused

    /// Rough severity ordering for sorting/badging (higher = worse).
    public var severity: Int {
        switch self {
        case .compromisedAndReused: return 3
        case .compromised: return 2
        case .reusedAcrossSites: return 1
        case .duplicatedWithinSite: return 0
        }
    }
}

/// A single finding: which credential(s) it involves, what kind, and (for
/// compromised entries) the breach count.
public struct AuditFinding: Identifiable, Sendable, Equatable {
    public let id: UUID
    public let kind: FindingKind
    /// The credentials this finding is about, by `ImportedCredential.id`.
    public let credentialIDs: [UUID]
    /// Breach occurrence count for compromised findings; nil otherwise.
    public let breachCount: Int?

    public init(
        id: UUID = UUID(),
        kind: FindingKind,
        credentialIDs: [UUID],
        breachCount: Int? = nil
    ) {
        self.id = id
        self.kind = kind
        self.credentialIDs = credentialIDs
        self.breachCount = breachCount
    }
}
