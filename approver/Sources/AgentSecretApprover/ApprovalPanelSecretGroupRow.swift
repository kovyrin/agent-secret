import Foundation

#if canImport(SwiftUI)
    import SwiftUI

    struct ApprovalPanelSecretGroupRow: View {
        private typealias Metric = ApprovalPanelStyle.Metric

        let group: SecretVaultGroupViewModel

        var body: some View {
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
                    Text(group.aliasSummary)
                        .font(.system(size: Metric.groupAliasFontSize, design: .monospaced))
                        .foregroundStyle(.secondary)
                        .lineLimit(Metric.twoLineLimit)
                        .truncationMode(.tail)
                }
                Spacer(minLength: Metric.inlineSpacing)
                Image(systemName: "chevron.down")
                    .font(.system(size: Metric.groupChevronFontSize, weight: .semibold))
                    .foregroundStyle(.secondary)
                    .accessibilityHidden(true)
            }
            .padding(.vertical, Metric.groupRowVerticalPadding)
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
    }
#endif
