import Foundation

/// Result of the Have I Been Pwned k-anonymity check for a single credential.
///
/// `unknown` is a first-class state, not an error: if the machine is offline or
/// a range request fails after retries, that entry is `unknown` and the rest of
/// the audit still completes.
public enum CompromisedStatus: Sendable, Equatable {
    /// Checked and not found in any known breach corpus.
    case clean
    /// Found in known breaches `breachCount` times.
    case compromised(breachCount: Int)
    /// Could not be determined (offline / request failed / not yet checked).
    case unknown

    public var isCompromised: Bool {
        if case .compromised = self { return true }
        return false
    }

    public var breachCount: Int? {
        if case let .compromised(count) = self { return count }
        return nil
    }
}
