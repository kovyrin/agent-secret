import Foundation

#if canImport(SwiftUI)
    import SwiftUI

    struct ApprovalPanelReasonCard: View {
        private typealias Metric = ApprovalPanelStyle.Metric
        private typealias Palette = ApprovalPanelStyle.Palette

        let reason: String

        var body: some View {
            HStack(alignment: .center, spacing: Metric.reasonCardSpacing) {
                Circle()
                    .fill(Palette.reasonAccent.opacity(Metric.reasonIconFillOpacity))
                    .frame(width: Metric.reasonIconCircleSize, height: Metric.reasonIconCircleSize)
                    .overlay {
                        Image(systemName: "bubble.left")
                            .font(.system(size: Metric.reasonIconSize, weight: .medium))
                            .foregroundStyle(Palette.reasonAccent)
                            .accessibilityHidden(true)
                    }

                VStack(alignment: .leading, spacing: Metric.reasonTextSpacing) {
                    Text("Reason")
                        .font(.system(size: Metric.sectionLabelFontSize, weight: .semibold))
                        .foregroundStyle(Palette.reasonAccent)
                    Text(reason)
                        .font(.system(size: Metric.reasonFontSize, weight: .bold, design: .rounded))
                        .foregroundStyle(Palette.reasonText)
                        .lineLimit(Metric.reasonLineLimit)
                        .minimumScaleFactor(Metric.reasonMinimumScaleFactor)
                }
                .layoutPriority(Metric.refLayoutPriority)
            }
            .padding(Metric.reasonCardPadding)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(panelBackground)
            .overlay(panelBorder)
        }

        private var panelBackground: some View {
            RoundedRectangle(cornerRadius: Metric.panelCornerRadius, style: .continuous)
                .fill(Palette.reasonAccent.opacity(Metric.reasonPanelOpacity))
        }

        private var panelBorder: some View {
            RoundedRectangle(cornerRadius: Metric.panelCornerRadius, style: .continuous)
                .stroke(Palette.reasonAccent.opacity(Metric.reasonBorderOpacity), lineWidth: Metric.borderWidth)
        }
    }
#endif
