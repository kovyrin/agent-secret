#if canImport(SwiftUI)
    import SwiftUI

    extension ApprovalRequestPanelView {
        private typealias Layout = ApprovalPanelLayout

        var resourceSection: some View {
            VStack(alignment: .leading, spacing: Layout.compactSpacing) {
                Text(viewModel.requestedResourcesHeading)
                    .font(.system(size: Layout.rowSpacing, weight: .semibold)).foregroundStyle(.secondary)
                VStack(spacing: 0) {
                    ForEach(Array(viewModel.accountGroups.enumerated()), id: \.offset) { _, group in
                        ApprovalPanelAccountGroup(group: group)
                    }
                }
                .background(ApprovalPanelTheme.raised)
                .clipShape(RoundedRectangle(cornerRadius: Layout.standardSpacing))
                .overlay(RoundedRectangle(cornerRadius: Layout.standardSpacing).stroke(ApprovalPanelTheme.border))
            }
        }
    }
#endif
