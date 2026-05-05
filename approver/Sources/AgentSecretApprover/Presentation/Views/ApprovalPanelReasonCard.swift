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
                    .fill(Color.green.opacity(Metric.reasonIconFillOpacity))
                    .frame(width: Metric.reasonIconCircleSize, height: Metric.reasonIconCircleSize)
                    .overlay {
                        Image(systemName: "bubble.left")
                            .font(.system(size: Metric.reasonIconSize, weight: .medium))
                            .foregroundStyle(Color.green)
                            .accessibilityHidden(true)
                    }

                VStack(alignment: .leading, spacing: Metric.reasonTextSpacing) {
                    Text("Reason")
                        .font(.system(size: Metric.sectionLabelFontSize, weight: .semibold))
                        .foregroundStyle(Color.green)
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
                .fill(Color.green.opacity(Metric.greenPanelOpacity))
        }

        private var panelBorder: some View {
            RoundedRectangle(cornerRadius: Metric.panelCornerRadius, style: .continuous)
                .stroke(Color.green.opacity(Metric.greenBorderOpacity), lineWidth: Metric.borderWidth)
        }
    }
#endif
