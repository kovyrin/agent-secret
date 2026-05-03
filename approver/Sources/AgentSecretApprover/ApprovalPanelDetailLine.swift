import Foundation

#if canImport(SwiftUI)
    import SwiftUI

    struct ApprovalPanelDetailLine: View {
        private typealias Metric = ApprovalPanelStyle.Metric

        let label: String
        let value: String

        var body: some View {
            HStack(alignment: .firstTextBaseline, spacing: Metric.inlineSpacing) {
                Text(label)
                    .fontWeight(.semibold)
                Text(value)
                    .font(.system(.body, design: .monospaced))
                    .foregroundStyle(.secondary)
                    .lineLimit(Metric.twoLineLimit)
                    .truncationMode(.middle)
            }
        }
    }
#endif
