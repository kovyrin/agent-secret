import Foundation

#if canImport(SwiftUI)
    import SwiftUI

    struct ApprovalPanelSecretListRow: View {
        private typealias Metric = ApprovalPanelStyle.Metric

        let secret: RequestedSecretRowViewModel
        let aliasColumnWidth: CGFloat

        var body: some View {
            HStack(spacing: Metric.secretListRowSpacing) {
                icon
                Text(secret.alias)
                    .font(.system(size: Metric.secretListAliasFontSize, weight: .semibold, design: .monospaced))
                    .lineLimit(Metric.singleLineLimit)
                    .frame(width: aliasColumnWidth, alignment: .leading)
                VStack(alignment: .leading, spacing: Metric.rowTextSpacing) {
                    Text(secret.ref)
                        .font(.system(size: Metric.secretListRefFontSize, design: .monospaced))
                        .foregroundStyle(.secondary)
                        .lineLimit(Metric.singleLineLimit)
                        .truncationMode(.middle)
                    Text(secret.accountLabel)
                        .font(.system(size: Metric.secretListRefFontSize))
                        .foregroundStyle(.secondary)
                        .lineLimit(Metric.singleLineLimit)
                }
                .layoutPriority(Metric.refLayoutPriority)
            }
        }

        private var icon: some View {
            Circle()
                .fill(Color.green.opacity(Metric.greenPanelOpacity + Metric.cautionPanelOpacity))
                .frame(width: Metric.secretListIconSize, height: Metric.secretListIconSize)
                .overlay {
                    Image(systemName: secret.symbolName)
                        .font(.system(size: Metric.secretListIconFontSize, weight: .medium))
                        .foregroundStyle(Color.green)
                        .accessibilityHidden(true)
                }
        }
    }
#endif
