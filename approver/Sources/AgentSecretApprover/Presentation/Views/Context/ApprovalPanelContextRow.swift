import Foundation

#if canImport(SwiftUI)
    import SwiftUI

    struct ApprovalPanelContextRow: View {
        private typealias Metric = ApprovalPanelStyle.Metric

        let icon: String
        let title: String
        let value: String
        let valueLineLimit: Int?

        var body: some View {
            HStack(alignment: .top, spacing: Metric.rowSpacing) {
                ApprovalPanelIconBox(systemName: icon)
                VStack(alignment: .leading, spacing: Metric.rowTextSpacing) {
                    Text(title)
                        .font(.system(size: Metric.contextTitleFontSize, weight: .semibold))
                    Text(value)
                        .font(.system(size: Metric.contextValueFontSize, design: .monospaced))
                        .lineLimit(valueLineLimit)
                        .truncationMode(.middle)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            .frame(maxWidth: .infinity, alignment: .topLeading)
        }

        init(
            icon: String,
            title: String,
            value: String,
            valueLineLimit: Int? = Metric.twoLineLimit
        ) {
            self.icon = icon
            self.title = title
            self.value = value
            self.valueLineLimit = valueLineLimit
        }
    }
#endif
