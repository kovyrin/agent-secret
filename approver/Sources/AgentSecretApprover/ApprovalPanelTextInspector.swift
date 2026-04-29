import Foundation

#if canImport(AppKit) && canImport(SwiftUI)
    import SwiftUI

    struct ApprovalPanelTextInspector: View {
        private typealias Metric = ApprovalPanelStyle.Metric

        @Environment(\.dismiss)
        private var dismiss

        let inspection: ApprovalPanelTextInspection

        var body: some View {
            VStack(alignment: .leading, spacing: Metric.sectionSpacing) {
                HStack {
                    Text(inspection.title)
                        .font(.system(size: Metric.detailTitleFontSize, weight: .semibold))
                    Spacer()
                    Button("Done") {
                        dismiss()
                    }
                    .keyboardShortcut(.defaultAction)
                }
                ScrollView {
                    Text(inspection.text)
                        .font(.system(size: Metric.contextValueFontSize, design: .monospaced))
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(Metric.secretPanelPadding)
                }
                .frame(width: Metric.inspectorWidth, height: Metric.inspectorHeight)
                .background(
                    RoundedRectangle(cornerRadius: Metric.panelCornerRadius, style: .continuous)
                        .fill(Color(nsColor: .textBackgroundColor))
                )
            }
            .padding(Metric.cardVerticalPadding)
        }
    }
#endif
