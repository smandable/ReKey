import Foundation

/// Heuristic for "important" domains — email, finance, identity, the big
/// platforms — so worst-first sorting can float high-value accounts to the top.
public enum DomainPriority {
    public static func isImportant(_ domain: String) -> Bool {
        if importantDomains.contains(domain) { return true }
        // Match keywords against the registrable domain's MAIN LABEL (the part
        // before the public suffix), and only as a whole label, prefix, or suffix —
        // never an interior substring. A bare `contains` floated innocuous domains
        // ("riverbankcafe.com") and was trivially gameable ("secure-bank-login.com")
        // while still catching the real "bankofamerica"/"mylocalbank"/"fastmail".
        let mainLabel = domain.split(separator: ".").first.map(String.init) ?? domain
        return keywords.contains { mainLabel == $0 || mainLabel.hasPrefix($0) || mainLabel.hasSuffix($0) }
    }

    /// Keyword fallback for the long tail (regional banks, mail hosts, …).
    static let keywords = ["bank", "mail", "crypto", "wallet"]

    static let importantDomains: Set<String> = [
        // Email / identity
        "google.com", "gmail.com", "googlemail.com", "apple.com", "icloud.com", "me.com",
        "microsoft.com", "live.com", "outlook.com", "hotmail.com", "office.com",
        "yahoo.com", "proton.me", "protonmail.com", "fastmail.com", "aol.com", "gmx.com", "zoho.com",
        "id.me", "login.gov", "irs.gov", "ssa.gov",
        // Money
        "paypal.com", "stripe.com", "square.com", "venmo.com", "cash.app", "wise.com",
        "coinbase.com", "binance.com", "kraken.com", "robinhood.com",
        "chase.com", "bankofamerica.com", "wellsfargo.com", "citi.com", "citibank.com",
        "capitalone.com", "americanexpress.com", "amex.com", "discover.com", "usbank.com",
        "schwab.com", "fidelity.com", "vanguard.com", "etrade.com",
        // Commerce / cloud / dev / social
        "amazon.com", "ebay.com", "walmart.com", "target.com",
        "dropbox.com", "box.com",
        "github.com", "gitlab.com", "bitbucket.org",
        "facebook.com", "instagram.com", "x.com", "twitter.com", "linkedin.com", "reddit.com",
        // Password managers themselves
        "1password.com", "lastpass.com", "bitwarden.com", "dashlane.com",
    ]
}
