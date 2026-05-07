import Foundation

#if canImport(SwiftUI)
    import SwiftUI

    struct ApprovalPanelResourceGroupList: View {
        private typealias Metric = ApprovalPanelStyle.Metric

        let heading: String
        let groups: [ResourceVaultGroupViewModel]

        @State private var expandedVaultNames: Set<String> = []

        var body: some View {
            VStack(alignment: .leading, spacing: Metric.groupListSpacing) {
                Text(heading)
                    .font(.system(size: Metric.sectionLabelFontSize, weight: .semibold))
                    .foregroundStyle(Color.green)
                VStack(spacing: Metric.zeroOffset) {
                    ForEach(groups, id: \.vaultName) { group in
                        ApprovalPanelResourceGroupRow(
                            group: group,
                            isExpanded: expandedVaultNames.contains(group.vaultName)
                        ) {
                            toggle(group)
                        }
                        if group.vaultName != groups.last?.vaultName {
                            Divider()
                        }
                    }
                }
            }
            .padding(Metric.resourcePanelPadding)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(panelBackground)
            .overlay(panelBorder)
        }

        private var panelBackground: some View {
            RoundedRectangle(cornerRadius: Metric.panelCornerRadius, style: .continuous)
                .fill(Color.green.opacity(Metric.greenPanelOpacity))
        }

        private var panelBorder: some View {
            RoundedRectangle(cornerRadius: Metric.panelCornerRadius, style: .continuous)
                .stroke(Color.green.opacity(Metric.greenBorderOpacity), lineWidth: Metric.borderWidth)
        }

        private func toggle(_ group: ResourceVaultGroupViewModel) {
            if expandedVaultNames.contains(group.vaultName) {
                expandedVaultNames.remove(group.vaultName)
            } else {
                expandedVaultNames.insert(group.vaultName)
            }
        }
    }
#endif
