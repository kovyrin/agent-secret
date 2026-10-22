@testable import AgentSecretApprover

#if canImport(AppKit) && canImport(SwiftUI)
    import SwiftUI

    /// Drives the production disclosure style through real native layout without OS input permissions.
    struct DisclosureGeometryFixture: View {
        private static let referenceCount = 30

        @ObservedObject var state: DisclosureGeometryState

        var body: some View {
            VStack {
                ScrollView {
                    DisclosureGroup("Synthetic resource details", isExpanded: $state.isExpanded) {
                        VStack {
                            ForEach(0 ..< Self.referenceCount, id: \.self) { index in
                                Text("Reference \(index): op://Example/Long synthetic item/credential")
                            }
                        }
                        .onAppear { state.contentVisible = true }
                        .onDisappear { state.contentVisible = false }
                    }
                    .disclosureGroupStyle(ApprovalPanelDisclosureStyle())
                }
                Text("Pinned synthetic decisions")
            }
        }
    }
#endif
