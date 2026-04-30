import Foundation

#if canImport(SwiftUI)
    import SwiftUI

    struct ApprovalPanelSecretGroupRow: View {
        private typealias Metric = ApprovalPanelStyle.Metric

        let group: SecretVaultGroupViewModel
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
                .accessibilityHint(isExpanded ? "Collapse requested secrets" : "Expand requested secrets")

                if isExpanded {
                    expandedSecrets
                        .padding(.top, Metric.groupSecretListTopPadding)
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

        private var expandedSecrets: some View {
            ScrollView {
                VStack(alignment: .leading, spacing: Metric.groupExpandedSecretListSpacing) {
                    ForEach(group.secrets, id: \.alias) { secret in
                        expandedRow(for: secret)
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            }
            .frame(height: expandedSecretListHeight)
            .scrollIndicators(.visible)
        }

        private var expandedSecretListHeight: CGFloat {
            let rowCount = CGFloat(group.secrets.count)
            let gapCount = CGFloat(max(Metric.singleSecretCount, group.secrets.count) - Metric.singleSecretCount)
            let contentHeight: CGFloat = rowCount * Metric.groupExpandedSecretRowEstimatedHeight +
                gapCount * Metric.groupExpandedSecretListSpacing
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

        private func expandedRow(for secret: RequestedSecretRowViewModel) -> some View {
            HStack(alignment: .top, spacing: Metric.secretListRowSpacing) {
                secretIcon(for: secret)
                VStack(alignment: .leading, spacing: Metric.rowTextSpacing) {
                    Text(secret.alias)
                        .font(.system(
                            size: Metric.groupExpandedSecretAliasFontSize,
                            weight: .semibold,
                            design: .monospaced
                        ))
                        .lineLimit(nil)
                        .fixedSize(horizontal: false, vertical: true)
                    Text(secret.ref)
                        .font(.system(size: Metric.groupExpandedRefFontSize, design: .monospaced))
                        .foregroundStyle(.secondary)
                        .lineLimit(nil)
                        .fixedSize(horizontal: false, vertical: true)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            }
            .padding(.vertical, Metric.groupExpandedSecretRowVerticalPadding)
        }

        private func secretIcon(for secret: RequestedSecretRowViewModel) -> some View {
            Circle()
                .fill(Color.green.opacity(Metric.greenPanelOpacity + Metric.cautionPanelOpacity))
                .frame(width: Metric.groupExpandedIconSize, height: Metric.groupExpandedIconSize)
                .overlay {
                    Image(systemName: secret.symbolName)
                        .font(.system(size: Metric.groupExpandedIconFontSize, weight: .medium))
                        .foregroundStyle(Color.green)
                        .accessibilityHidden(true)
                }
        }
    }
#endif
