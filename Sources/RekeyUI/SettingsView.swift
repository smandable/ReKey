import SwiftUI

/// App settings: password display and the defaults used when generating
/// replacement passwords. All values persist in UserDefaults (no passwords).
struct SettingsView: View {
    @AppStorage(Prefs.showPasswords) private var showPasswords = true
    @AppStorage(Prefs.defaultPwStyle) private var defaultPwStyle = Prefs.styleStrong
    @AppStorage(Prefs.defaultPwLength) private var defaultPwLength = Prefs.defaultLength
    @AppStorage(Prefs.avoidLookAlikes) private var avoidLookAlikes = false

    private let styles = [Prefs.styleStrong, Prefs.styleLettersDigits, Prefs.stylePassphrase]

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                Text("Settings").font(.largeTitle.bold())

                GroupBox {
                    VStack(alignment: .leading, spacing: 8) {
                        Toggle("Show passwords in the audit list and Fix Queue", isOn: $showPasswords)
                        Text("When off, passwords are masked by default. You can still reveal individual ones with the eye button.")
                            .font(.caption).foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    .padding(8).frame(maxWidth: .infinity, alignment: .leading)
                } label: { Label("Display", systemImage: "eye") }

                GroupBox {
                    VStack(alignment: .leading, spacing: 12) {
                        Text("Used when Rekey generates a replacement in the Fix Queue. You can still change any of these per item.")
                            .font(.caption).foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)

                        HStack(spacing: 8) {
                            Text("Type").frame(width: 70, alignment: .leading).foregroundStyle(.secondary)
                            // Buttons rather than a segmented Picker, which is
                            // unreliable here (same quirk as the sidebar List).
                            ForEach(styles, id: \.self) { style in
                                Button {
                                    defaultPwStyle = style
                                } label: {
                                    Text(style)
                                        .padding(.vertical, 4).padding(.horizontal, 10)
                                        .background(defaultPwStyle == style ? AnyShapeStyle(Color.accentColor) : AnyShapeStyle(.clear))
                                        .foregroundStyle(defaultPwStyle == style ? AnyShapeStyle(.white) : AnyShapeStyle(.primary))
                                        .clipShape(RoundedRectangle(cornerRadius: 6))
                                        .contentShape(Rectangle())
                                }
                                .buttonStyle(.plain)
                            }
                        }

                        if defaultPwStyle != Prefs.stylePassphrase {
                            HStack(spacing: 8) {
                                Text("Length").frame(width: 70, alignment: .leading).foregroundStyle(.secondary)
                                Stepper("\(defaultPwLength)", value: $defaultPwLength, in: 12...64)
                                    .frame(width: 120)
                            }
                            HStack(spacing: 6) {
                                Toggle("No look-alikes", isOn: $avoidLookAlikes)
                                HelpHint("\"No look-alikes\" excludes the characters that are easy to confuse when reading or typing a password by hand — capital I, lowercase l, the digit 1, capital O, and zero 0.")
                            }
                        } else {
                            Text("Passphrases use a diceware word list; length and look-alike options don't apply.")
                                .font(.caption).foregroundStyle(.secondary)
                        }
                    }
                    .padding(8).frame(maxWidth: .infinity, alignment: .leading)
                } label: { Label("New password defaults", systemImage: "key") }
            }
            .padding(20)
            .frame(maxWidth: 640, alignment: .leading)
        }
        .frame(maxWidth: .infinity)
    }
}
