import Foundation

#if canImport(SwiftUI)
    import SwiftUI

    struct ApprovalPanelPillText: View {
        private typealias Metric = ApprovalPanelStyle.Metric

        let text: String

        var body: some View {
            Text(text)
                .font(.system(size: Metric.detailTitleFontSize, weight: .medium, design: .monospaced))
                .foregroundStyle(Color.green)
                .lineLimit(Metric.singleLineLimit)
                .truncationMode(.middle)
                .padding(.horizontal, Metric.pillHorizontalPadding)
                .padding(.vertical, Metric.pillVerticalPadding)
                .background(pillBackground)
        }

        private var pillBackground: some View {
            RoundedRectangle(cornerRadius: Metric.pillCornerRadius, style: .continuous)
                .fill(Color.green.opacity(Metric.subtleFillOpacity))
                .overlay(
                    RoundedRectangle(cornerRadius: Metric.pillCornerRadius, style: .continuous)
                        .stroke(Color.gray.opacity(Metric.subtleBorderOpacity), lineWidth: Metric.borderWidth)
                )
        }
    }
#endif
