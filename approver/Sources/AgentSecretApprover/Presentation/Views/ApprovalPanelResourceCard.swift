import Foundation

#if canImport(SwiftUI)
    import SwiftUI

    struct ApprovalPanelResourceCard: View {
        private typealias Metric = ApprovalPanelStyle.Metric

        let resource: RequestedResourceRowViewModel

        var body: some View {
            HStack(spacing: Metric.contextRowSpacing) {
                ZStack {
                    Circle()
                        .fill(Color.green.opacity(Metric.greenPanelOpacity + Metric.cautionPanelOpacity))
                    Image(systemName: resource.symbolName)
                        .font(.system(size: Metric.footerIconSize, weight: .semibold))
                        .foregroundStyle(Color.green)
                        .accessibilityHidden(true)
                }
                .frame(width: Metric.resourceIconSize, height: Metric.resourceIconSize)
                VStack(alignment: .leading, spacing: Metric.detailSpacing) {
                    Text(resource.alias)
                        .font(.system(size: Metric.iconFontSize, weight: .semibold, design: .monospaced))
                    ApprovalPanelResourceReferenceText(
                        segments: resource.refSegments,
                        fontSize: Metric.detailTitleFontSize,
                        lineLimit: Metric.twoLineLimit
                    )
                    .truncationMode(.middle)
                    Text(resource.accountLabel)
                        .font(.system(size: Metric.detailSubtitleFontSize))
                        .foregroundStyle(.secondary)
                        .lineLimit(Metric.singleLineLimit)
                }
            }
        }
    }
#endif
