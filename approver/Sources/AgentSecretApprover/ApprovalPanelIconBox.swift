import Foundation

#if canImport(SwiftUI)
    import SwiftUI

    struct ApprovalPanelIconBox: View {
        private typealias Metric = ApprovalPanelStyle.Metric

        let systemName: String

        var body: some View {
            RoundedRectangle(cornerRadius: Metric.iconBoxCornerRadius, style: .continuous)
                .fill(Color.white.opacity(Metric.iconBoxFillOpacity))
                .overlay(
                    RoundedRectangle(cornerRadius: Metric.iconBoxCornerRadius, style: .continuous)
                        .stroke(Color.gray.opacity(Metric.greenBorderOpacity), lineWidth: Metric.borderWidth)
                )
                .frame(width: Metric.iconBoxSize, height: Metric.iconBoxSize)
                .overlay {
                    Image(systemName: systemName)
                        .font(.system(size: Metric.iconFontSize, weight: .medium))
                        .foregroundStyle(.primary)
                        .accessibilityHidden(true)
                }
        }
    }
#endif
