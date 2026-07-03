import SwiftUI
import Model

/// The standalone **Generate** tab: make a one-off password or passphrase
/// without going through the audit → fix workflow — for a new signup, a Wi-Fi
/// password, anything. Nothing here is tied to a credential or saved anywhere;
/// Copy uses the Fix Queue's clipboard hygiene (concealed marker, timed
/// auto-clear, clear-on-quit).
///
/// Not paywalled in the App Store build: the IAP gates the fix *workflow*; a
/// generator is a free-standing utility that never touches a store.
struct GeneratorView: View {
    @Bindable var model: AppModel

    /// Shown vs. masked, seeded from the app-wide display preference like the
    /// fix cards. Generating usually means you want to see it, but the default
    /// stays consistent with the rest of the app.
    @State private var revealed: Bool
    @State private var copied = false

    init(model: AppModel) {
        self.model = model
        _revealed = State(initialValue: Prefs.showPasswordsValue())
    }

    private var clearSeconds: Int {
        Int(model.fixQueue.clipboardClearAfter.components.seconds)
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                Text("Generate").font(.largeTitle.bold())
                Text("A fresh password or passphrase, created on your Mac by the same generator the Fix Queue uses — cryptographically secure, no network. ReKey doesn't save it: copy it into the site and let your password manager store it; once you regenerate or quit, it's gone.")
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)

                GroupBox {
                    VStack(alignment: .leading, spacing: 12) {
                        valueRow
                        if let error = model.generatorPanel.lastError {
                            Label(error, systemImage: "exclamationmark.triangle.fill")
                                .font(.caption).foregroundStyle(.orange)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                        Divider()
                        optionsRows
                        Divider()
                        actionRow
                    }
                    .padding(8)
                }
            }
            .padding(20)
            .frame(maxWidth: 640, alignment: .leading)
        }
        .frame(maxWidth: .infinity)
        // First value is made lazily here, not at launch — no password material
        // exists until the tab is actually visited.
        .onAppear { model.generatorPanel.ensureGenerated() }
    }

    private var valueRow: some View {
        HStack(alignment: .firstTextBaseline, spacing: 4) {
            Text(displayValue)
                .font(.system(.title3, design: .monospaced))
                .textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
                .frame(maxWidth: .infinity, alignment: .leading)
                .accessibilityLabel(revealed ? "Generated password" : "Generated password, hidden")
            Button { model.generatorPanel.regenerate() } label: {
                Image(systemName: "arrow.clockwise").frame(width: Self.iconWidth)
            }
            .buttonStyle(.borderless)
            .help("Generate another")
            .accessibilityLabel("Generate another")
            Button { revealed.toggle() } label: {
                Image(systemName: revealed ? "eye.slash" : "eye").frame(width: Self.iconWidth)
            }
            .buttonStyle(.borderless)
            .help(revealed ? "Hide" : "Reveal")
            .accessibilityLabel(revealed ? "Hide password" : "Reveal password")
        }
    }

    private static let iconWidth: CGFloat = 22

    private var displayValue: String {
        guard let secret = model.generatorPanel.current else { return "—" }
        return revealed ? secret.reveal() : secret.masked()
    }

    private var optionsRows: some View {
        @Bindable var panel = model.generatorPanel
        return VStack(alignment: .leading, spacing: 10) {
            styleSelector
            HStack(spacing: 12) {
                if panel.style == .passphrase {
                    Stepper("Words: \(panel.wordCount)", value: $panel.wordCount, in: GeneratorPanel.wordCountRange)
                    HelpHint("Passphrases draw words from the EFF diceware list (7,776 words) — long, but memorable and easy to type. Six words is a strong default.")
                } else {
                    Stepper("Length \(panel.length)", value: $panel.length, in: GeneratorPanel.lengthRange)
                    Toggle("No look-alikes", isOn: $panel.avoidLookAlikes)
                    HelpHint("\"No look-alikes\" excludes the characters that are easy to confuse when reading or typing a password by hand — capital I, lowercase l, the digit 1, capital O, and zero 0.")
                }
                Spacer()
                Text("≈ \(panel.entropyBits) bits")
                    .foregroundStyle(.secondary)
                    .help("Estimated strength: how many random bits an attacker would have to guess. 77+ bits (a 6-word passphrase) is strong; 100+ is excellent.")
            }
            .font(.caption)
        }
    }

    /// Segmented-style picker built from plain Buttons — a native segmented
    /// `Picker` is unreliable on this macOS (same control-selection quirk as
    /// the sidebar `List`), so this mirrors the fix card's selector.
    private var styleSelector: some View {
        let panel = model.generatorPanel
        return HStack(spacing: 0) {
            ForEach(GeneratorPanel.Style.allCases) { option in
                // Passphrases need the bundled wordlist; if it failed to load
                // (corrupt bundle), disable the choice instead of erroring on it.
                let unavailable = option == .passphrase && !panel.canGeneratePassphrases
                Button {
                    panel.style = option
                } label: {
                    Text(option.rawValue)
                        .font(.caption)
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 4)
                        .padding(.horizontal, 8)
                        .foregroundStyle(panel.style == option ? AnyShapeStyle(.white) : AnyShapeStyle(.primary))
                        .background(panel.style == option ? AnyShapeStyle(Color.accentColor) : AnyShapeStyle(.clear))
                        .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .disabled(unavailable)
                .help(unavailable ? "Passphrases are unavailable — the bundled word list couldn't be loaded." : "")
            }
        }
        .frame(width: 300)
        .background(.quaternary, in: RoundedRectangle(cornerRadius: 6))
        .clipShape(RoundedRectangle(cornerRadius: 6))
        .overlay(RoundedRectangle(cornerRadius: 6).strokeBorder(.quaternary))
    }

    private var actionRow: some View {
        HStack(alignment: .firstTextBaseline, spacing: 12) {
            Button {
                model.copyGeneratedPassword()
                flashCopied()
            } label: {
                Label(copied ? "Copied" : "Copy", systemImage: copied ? "checkmark" : "doc.on.doc")
            }
            .buttonStyle(.borderedProminent)
            .disabled(model.generatorPanel.current == nil)
            Text("The clipboard auto-clears ~\(clearSeconds)s after you copy (unless you've copied something else since), and it's marked concealed so clipboard-history managers that honor the convention keep it out of their history.")
                .font(.caption).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    private func flashCopied() {
        copied = true
        Task { @MainActor in
            try? await Task.sleep(for: .seconds(1.5))
            copied = false
        }
    }
}
