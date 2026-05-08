import Foundation

#if canImport(SwiftUI)
    import SwiftUI

    struct ApprovalPanelResourceGroupRow: View {
        private typealias Metric = ApprovalPanelStyle.Metric

        let group: ResourceVaultGroupViewModel
        let isExpanded: Bool
        let toggle: () -> Void

        var body: some View {
            VStack(alignment: .leading, spacing: Metric.zeroOffset) {
                Button(action: toggle) {
                    summary
                }
                .buttonStyle(.plain)
                .contentShape(Rectangle())
                .accessibilityLabel("\(group.vaultName), \(group.countLabel)")
                .accessibilityHint(isExpanded ? "Collapse requested resources" : "Expand requested resources")

                if isExpanded {
                    expandedResources
                        .padding(.top, Metric.groupResourceListTopPadding)
                }
            }
            .padding(.vertical, Metric.groupRowVerticalPadding)
        }

        private var summary: some View {
            HStack(spacing: Metric.groupRowSpacing) {
                icon
                VStack(alignment: .leading, spacing: Metric.detailLabelSpacing) {
                    HStack(spacing: Metric.inlineSpacing) {
                        Text(group.vaultName)
                            .font(.system(size: Metric.groupTitleFontSize, weight: .semibold))
                        Text(group.countLabel)
                            .font(.system(size: Metric.groupCountFontSize))
                            .foregroundStyle(.secondary)
                    }
                    if !isExpanded {
                        Text(group.aliasSummary)
                            .font(.system(size: Metric.groupAliasFontSize, design: .monospaced))
                            .foregroundStyle(.secondary)
                            .lineLimit(Metric.twoLineLimit)
                            .truncationMode(.tail)
                            .fixedSize(horizontal: false, vertical: true)
                            .layoutPriority(Metric.refLayoutPriority)
                    }
                }
                Spacer(minLength: Metric.inlineSpacing)
                Image(systemName: "chevron.down")
                    .font(.system(size: Metric.groupChevronFontSize, weight: .semibold))
                    .foregroundStyle(.secondary)
                    .rotationEffect(.degrees(isExpanded ? Metric.groupChevronExpandedDegrees : Metric.zeroOffset))
                    .accessibilityHidden(true)
            }
        }

        private var expandedResources: some View {
            ScrollView {
                VStack(alignment: .leading, spacing: Metric.groupExpandedResourceListSpacing) {
                    ForEach(group.resources, id: \.alias) { resource in
                        expandedRow(for: resource)
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            }
            .frame(height: expandedResourceListHeight)
            .scrollIndicators(.visible)
        }

        private var expandedResourceListHeight: CGFloat {
            let rowCount = CGFloat(group.resources.count)
            let gapCount = CGFloat(max(Metric.singleResourceCount, group.resources.count) - Metric.singleResourceCount)
            let contentHeight: CGFloat = rowCount * Metric.groupExpandedResourceRowEstimatedHeight +
                gapCount * Metric.groupExpandedResourceListSpacing
            return min(contentHeight, Metric.groupExpandedListMaxHeight)
        }

        private var icon: some View {
            Circle()
                .fill(Color.green.opacity(Metric.iconBoxFillOpacity))
                .frame(width: Metric.groupIconSize, height: Metric.groupIconSize)
                .overlay {
                    Text(group.vaultName.prefix(Metric.groupIconCharacterCount).uppercased())
                        .font(.system(size: Metric.groupIconFontSize, weight: .bold, design: .rounded))
                        .foregroundStyle(Color.green)
                }
        }

        private func expandedRow(for resource: RequestedResourceRowViewModel) -> some View {
            HStack(alignment: .top, spacing: Metric.resourceListRowSpacing) {
                resourceIcon(for: resource)
                VStack(alignment: .leading, spacing: Metric.rowTextSpacing) {
                    Text(resource.alias)
                        .font(.system(
                            size: Metric.groupExpandedResourceAliasFontSize,
                            weight: .semibold,
                            design: .monospaced
                        ))
                        .lineLimit(nil)
                        .fixedSize(horizontal: false, vertical: true)
                    ApprovalPanelResourceReferenceText(
                        segments: resource.refSegments,
                        fontSize: Metric.groupExpandedRefFontSize,
                        lineLimit: nil
                    )
                    .fixedSize(horizontal: false, vertical: true)
                    Text(resource.accountLabel)
                        .font(.system(size: Metric.groupExpandedRefFontSize))
                        .foregroundStyle(.secondary)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            }
            .padding(.vertical, Metric.groupExpandedResourceRowVerticalPadding)
        }

        private func resourceIcon(for resource: RequestedResourceRowViewModel) -> some View {
            Circle()
                .fill(Color.green.opacity(Metric.greenPanelOpacity + Metric.cautionPanelOpacity))
                .frame(width: Metric.groupExpandedIconSize, height: Metric.groupExpandedIconSize)
                .overlay {
                    Image(systemName: resource.symbolName)
                        .font(.system(size: Metric.groupExpandedIconFontSize, weight: .medium))
                        .foregroundStyle(Color.green)
                        .accessibilityHidden(true)
                }
        }
    }
#endif
