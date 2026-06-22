import SwiftUI

/// The app's main window: a sidebar (Import / Findings / Fix Queue / Clean Up)
/// and a detail pane that swaps with the selected section.
public struct RootView: View {
    @State private var model = AppModel()
    @AppStorage(Prefs.keepOnTop) private var keepOnTop = true

    public init() {}

    public var body: some View {
        NavigationSplitView {
            // A plain ScrollView + VStack of Button rows — NOT a `List`. Two of
            // this macOS's SwiftUI bugs bite the sidebar: `List(selection:)` is
            // inert (no row highlights/activates), and a `List` of custom rows
            // intermittently renders EMPTY when the detail swaps to certain views.
            // Buttons set the section directly and draw their own highlight.
            ScrollView {
                VStack(spacing: 2) {
                    ForEach(AppModel.Section.sidebar) { section in
                        SidebarRow(
                            section: section,
                            isSelected: model.section == section,
                            badge: badge(for: section)
                        ) {
                            model.section = section
                        }
                    }
                }
                .padding(.horizontal, 8)
                .padding(.vertical, 6)
            }
            .navigationSplitViewColumnWidth(min: 180, ideal: 200, max: 240)
            .navigationTitle("ReKey")
        } detail: {
            detail
        }
        // Float above the browser change page ReKey opens, so it isn't buried.
        .background(WindowLevelModifier(keepOnTop: keepOnTop))
    }

    @ViewBuilder
    private var detail: some View {
        switch model.section {
        case .importing: ImportView(model: model)
        case .findings: FindingsView(model: model)
        case .fixing: FixQueueView(model: model)
        case .cull: CullView(model: model)
        case .cleanup: CleanupView(model: model)
        case .help: HelpView(model: model)
        case .settings: SettingsView()
        }
    }

    private func badge(for section: AppModel.Section) -> Int {
        switch section {
        case .importing: return model.files.count
        case .findings: return model.report?.findingsByCredential.count ?? 0
        case .fixing: return model.fixQueue.items.filter { $0.status == .pending }.count
        case .cull: return model.markedForDeletionCount
        case .cleanup: return 0
        case .help: return 0
        case .settings: return 0
        }
    }
}

/// One clickable sidebar entry, drawn to mimic a selected `.sidebar` list row.
private struct SidebarRow: View {
    let section: AppModel.Section
    let isSelected: Bool
    let badge: Int
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            HStack {
                Label(section.rawValue, systemImage: section.systemImage)
                Spacer()
                if badge > 0 {
                    Text("\(badge)")
                        .font(.caption.weight(.medium))
                        .foregroundStyle(isSelected ? AnyShapeStyle(.white.opacity(0.85)) : AnyShapeStyle(.secondary))
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.vertical, 5)
            .padding(.horizontal, 8)
            .contentShape(Rectangle())
            .background(
                RoundedRectangle(cornerRadius: 6)
                    .fill(isSelected ? AnyShapeStyle(Color.accentColor) : AnyShapeStyle(Color.clear))
            )
        }
        .buttonStyle(.plain)
        .foregroundStyle(isSelected ? AnyShapeStyle(.white) : AnyShapeStyle(.primary))
    }
}
