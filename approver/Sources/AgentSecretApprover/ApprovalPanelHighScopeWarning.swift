import Foundation

#if canImport(SwiftUI)
    import SwiftUI

    struct ApprovalPanelHighScopeWarning: View {
        private typealias Metric = ApprovalPanelStyle.Metric
        private typealias Palette = ApprovalPanelStyle.Palette

        let printsEnvironmentWarning: Bool
        let secretCount: Int

        var body: some View {
            HStack(alignment: .top, spacing: Metric.cautionSpacing) {
                Image(systemName: "exclamationmark.triangle")
                    .font(.system(size: Metric.cautionIconSize, weight: .semibold))
                    .foregroundStyle(Color.orange)
                    .accessibilityHidden(true)
                VStack(alignment: .leading, spacing: Metric.detailLabelSpacing) {
                    Text("High-scope request")
                        .fontWeight(.semibold)
                    Text("This command is requesting access to \(secretCount) secrets.")
                    if printsEnvironmentWarning {
                        Text("It can also print environment variables.")
                    }
                    Text("Approve only if this matches the task you asked the agent to run.")
                }
            }
            .font(.system(size: Metric.bodyFontSize))
            .foregroundStyle(Palette.cautionText)
            .padding(Metric.cautionPadding)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(background)
            .overlay(border)
        }

        private var background: some View {
            RoundedRectangle(cornerRadius: Metric.cautionCornerRadius, style: .continuous)
                .fill(Color.orange.opacity(Metric.cautionPanelOpacity))
        }

        private var border: some View {
            RoundedRectangle(cornerRadius: Metric.cautionCornerRadius, style: .continuous)
                .stroke(Color.orange.opacity(Metric.cautionBorderOpacity), lineWidth: Metric.borderWidth)
        }
    }
#endif
