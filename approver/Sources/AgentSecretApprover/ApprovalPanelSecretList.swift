import Foundation

#if canImport(SwiftUI)
    import SwiftUI

    struct ApprovalPanelSecretList: View {
        private typealias Metric = ApprovalPanelStyle.Metric

        let heading: String
        let secrets: [RequestedSecretRowViewModel]

        var body: some View {
            VStack(alignment: .leading, spacing: Metric.secretListSpacing) {
                Text(heading)
                    .font(.system(size: Metric.sectionLabelFontSize, weight: .semibold))
                    .foregroundStyle(Color.green)
                ForEach(secrets, id: \.alias) { secret in
                    ApprovalPanelSecretListRow(secret: secret)
                }
            }
            .padding(Metric.secretPanelPadding)
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
