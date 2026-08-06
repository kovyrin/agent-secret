import Foundation

#if canImport(AppKit) && canImport(SwiftUI)
    import SwiftUI

    struct ApprovalRequestContextSection: View {
        private typealias Metric = ApprovalPanelStyle.Metric

        let viewModel: ApprovalRequestViewModel
        var body: some View {
            Grid(
                alignment: .topLeading,
                horizontalSpacing: Metric.contextColumnSpacing,
                verticalSpacing: Metric.contextSectionSpacing
            ) {
                GridRow {
                    ApprovalPanelContextRow(
                        icon: "terminal",
                        title: "Command",
                        value: viewModel.command,
                        valueLineLimit: Metric.commandPreviewLineLimit
                    )
                    .gridCellColumns(Metric.contextColumnCount)
                }

                GridRow {
                    ApprovalPanelContextRow(
                        icon: "folder",
                        title: "Project folder",
                        value: viewModel.projectFolder
                    )
                    ApprovalPanelContextRow(
                        icon: "scope",
                        title: "Scope",
                        value: viewModel.scopeSummary,
                        valueLineLimit: Metric.scopePreviewLineLimit
                    )
                }
            }
            .frame(maxWidth: .infinity, alignment: .topLeading)
        }
    }
#endif
