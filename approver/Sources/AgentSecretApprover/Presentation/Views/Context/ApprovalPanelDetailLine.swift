import Foundation

#if canImport(SwiftUI)
    import SwiftUI

    struct ApprovalPanelDetailLine: View {
        private typealias Metric = ApprovalPanelStyle.Metric

        let label: String
        let value: String

        var body: some View {
            VStack(alignment: .leading, spacing: Metric.rowTextSpacing) {
                Text(label)
                    .fontWeight(.semibold)
                Text(value)
                    .font(.system(size: Metric.contextValueFontSize, design: .monospaced))
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                    .textSelection(.enabled)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }
#endif
