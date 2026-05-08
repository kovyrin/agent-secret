import Foundation

#if canImport(AppKit) && canImport(SwiftUI)
    import SwiftUI

    struct ApprovalRequestContextSection: View {
        private typealias Metric = ApprovalPanelStyle.Metric

        let viewModel: ApprovalRequestViewModel
        @Binding var textInspection: ApprovalPanelTextInspection?

        var body: some View {
            VStack(alignment: .leading, spacing: Metric.contextSectionSpacing) {
                ApprovalPanelContextRow(
                    icon: "terminal",
                    title: "Command",
                    value: viewModel.command,
                    valueLineLimit: Metric.commandPreviewLineLimit,
                    inspectAction: commandInspectionAction
                )
                .frame(maxWidth: .infinity, alignment: .topLeading)

                HStack(alignment: .top, spacing: Metric.contextColumnSpacing) {
                    ApprovalPanelContextRow(
                        icon: "folder",
                        title: "Project folder",
                        value: viewModel.projectFolder,
                        inspectAction: requestScopeInspectionAction
                    )
                    .frame(maxWidth: .infinity, alignment: .topLeading)

                    ApprovalPanelContextRow(
                        icon: "scope",
                        title: "Scope",
                        value: viewModel.scopeSummary,
                        valueLineLimit: Metric.scopePreviewLineLimit,
                        inspectAction: requestScopeInspectionAction
                    )
                    .frame(maxWidth: .infinity, alignment: .topLeading)
                }
            }
        }

        private var commandInspectionAction: (() -> Void)? {
            guard viewModel.commandNeedsInspector else {
                return nil
            }
            return {
                textInspection = ApprovalPanelTextInspection(
                    title: "Command arguments",
                    text: viewModel.commandInspectionText
                )
            }
        }

        private var requestScopeInspectionAction: () -> Void {
            {
                textInspection = ApprovalPanelTextInspection(
                    title: "Full request scope",
                    text: viewModel.requestInspectionText
                )
            }
        }
    }
#endif
