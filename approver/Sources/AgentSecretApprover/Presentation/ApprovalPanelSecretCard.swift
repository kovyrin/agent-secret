import Foundation

#if canImport(SwiftUI)
    import SwiftUI

    struct ApprovalPanelSecretCard: View {
        private typealias Metric = ApprovalPanelStyle.Metric

        let secret: RequestedSecretRowViewModel

        var body: some View {
            HStack(spacing: Metric.contextRowSpacing) {
                ZStack {
                    Circle()
                        .fill(Color.green.opacity(Metric.greenPanelOpacity + Metric.cautionPanelOpacity))
                    Image(systemName: secret.symbolName)
                        .font(.system(size: Metric.footerIconSize, weight: .semibold))
                        .foregroundStyle(Color.green)
                        .accessibilityHidden(true)
                }
                .frame(width: Metric.secretIconSize, height: Metric.secretIconSize)
                VStack(alignment: .leading, spacing: Metric.detailSpacing) {
                    Text(secret.alias)
                        .font(.system(size: Metric.iconFontSize, weight: .semibold, design: .monospaced))
                    Text(secret.ref)
                        .font(.system(size: Metric.detailTitleFontSize, design: .monospaced))
                        .lineLimit(Metric.twoLineLimit)
                        .truncationMode(.middle)
                    if let accountLabel: String = secret.accountLabel {
                        Text(accountLabel)
                            .font(.system(size: Metric.detailSubtitleFontSize))
                            .foregroundStyle(.secondary)
                            .lineLimit(Metric.singleLineLimit)
                    }
                }
            }
        }
    }
#endif
