import Foundation

#if canImport(SwiftUI)
    import SwiftUI

    struct ApprovalPanelContextRow: View {
        private typealias Metric = ApprovalPanelStyle.Metric

        let icon: String
        let title: String
        let value: String
        let valueLineLimit: Int?
        let inspectAction: (() -> Void)?

        var body: some View {
            HStack(alignment: .top, spacing: Metric.rowSpacing) {
                ApprovalPanelIconBox(systemName: icon)
                VStack(alignment: .leading, spacing: Metric.rowTextSpacing) {
                    HStack(spacing: Metric.inlineSpacing) {
                        Text(title)
                            .font(.system(size: Metric.contextTitleFontSize, weight: .semibold))
                        if let inspectAction {
                            Button("View full", action: inspectAction)
                                .buttonStyle(.plain)
                                .font(.system(size: Metric.detailSubtitleFontSize, weight: .medium))
                                .foregroundStyle(Color.green)
                        }
                    }
                    Text(value)
                        .font(.system(size: Metric.contextValueFontSize, design: .monospaced))
                        .lineLimit(valueLineLimit)
                        .truncationMode(.middle)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
        }

        init(
            icon: String,
            title: String,
            value: String,
            valueLineLimit: Int? = Metric.twoLineLimit,
            inspectAction: (() -> Void)? = nil
        ) {
            self.icon = icon
            self.title = title
            self.value = value
            self.valueLineLimit = valueLineLimit
            self.inspectAction = inspectAction
        }
    }
#endif
