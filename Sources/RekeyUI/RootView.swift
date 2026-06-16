import SwiftUI

/// The app's main window: a sidebar (Import / Findings / Fix Queue) and a detail
/// pane that swaps with the selected section.
public struct RootView: View {
    @State private var model = AppModel()

    public init() {}

    public var body: some View {
        @Bindable var model = model

        NavigationSplitView {
            List(selection: sectionSelection) {
                ForEach(AppModel.Section.allCases) { section in
                    Label(section.rawValue, systemImage: section.systemImage)
                        .tag(section)
                        .badge(badge(for: section))
                }
            }
            .navigationSplitViewColumnWidth(min: 180, ideal: 200, max: 240)
            .navigationTitle("Rekey")
        } detail: {
            detail
        }
    }

    private var sectionSelection: Binding<AppModel.Section?> {
        Binding(
            get: { model.section },
            set: { if let new = $0 { model.section = new } }
        )
    }

    @ViewBuilder
    private var detail: some View {
        switch model.section {
        case .importing: ImportView(model: model)
        case .findings: FindingsView(model: model)
        case .fixing: FixQueueView(model: model)
        case .cleanup: CleanupView(model: model)
        }
    }

    private func badge(for section: AppModel.Section) -> Int {
        switch section {
        case .importing: return model.files.count
        case .findings: return model.report?.findingsByCredential.count ?? 0
        case .fixing: return model.fixQueue.items.filter { $0.status == .pending }.count
        case .cleanup: return 0
        }
    }
}
