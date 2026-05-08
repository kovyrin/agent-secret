import Foundation

#if canImport(SwiftUI)
    import SwiftUI

    struct ApprovalPanelResourceListRow: View {
        private typealias Metric = ApprovalPanelStyle.Metric

        let resource: RequestedResourceRowViewModel
        let aliasColumnWidth: CGFloat

        var body: some View {
            HStack(spacing: Metric.resourceListRowSpacing) {
                icon
                Text(resource.alias)
                    .font(.system(size: Metric.resourceListAliasFontSize, weight: .semibold, design: .monospaced))
                    .lineLimit(Metric.singleLineLimit)
                    .frame(width: aliasColumnWidth, alignment: .leading)
                VStack(alignment: .leading, spacing: Metric.rowTextSpacing) {
                    ApprovalPanelResourceReferenceText(
                        segments: resource.refSegments,
                        fontSize: Metric.resourceListRefFontSize,
                        lineLimit: Metric.singleLineLimit
                    )
                    .lineLimit(Metric.singleLineLimit)
                    .truncationMode(.middle)
                    Text(resource.accountLabel)
                        .font(.system(size: Metric.resourceListRefFontSize))
                        .foregroundStyle(.secondary)
                        .lineLimit(Metric.singleLineLimit)
                }
                .layoutPriority(Metric.refLayoutPriority)
            }
        }

        private var icon: some View {
            Circle()
                .fill(Color.green.opacity(Metric.greenPanelOpacity + Metric.cautionPanelOpacity))
                .frame(width: Metric.resourceListIconSize, height: Metric.resourceListIconSize)
                .overlay {
                    Image(systemName: resource.symbolName)
                        .font(.system(size: Metric.resourceListIconFontSize, weight: .medium))
                        .foregroundStyle(Color.green)
                        .accessibilityHidden(true)
                }
        }
    }
#endif
