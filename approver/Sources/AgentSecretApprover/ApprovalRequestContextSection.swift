import Foundation

#if canImport(AppKit) && canImport(SwiftUI)
    import SwiftUI

    struct ApprovalRequestContextSection: View {
        private typealias Metric = ApprovalPanelStyle.Metric

        let viewModel: ApprovalRequestViewModel
        @Binding var textInspection: ApprovalPanelTextInspection?

        var body: some View {
            VStack(alignment: .leading, spacing: Metric.contextRowSpacing) {
                ApprovalPanelContextRow(
                    icon: "bubble.left",
                    title: "Reason",
                    value: viewModel.reason,
                    valueLineLimit: nil
                )
                ApprovalPanelContextRow(
                    icon: "terminal",
                    title: "Command",
                    value: viewModel.command,
                    inspectAction: commandInspectionAction
                )
                ApprovalPanelContextRow(
                    icon: "folder",
                    title: "Project folder",
                    value: viewModel.projectFolder,
                    inspectAction: requestScopeInspectionAction
                )
                ApprovalPanelContextRow(
                    icon: "scope",
                    title: "Scope",
                    value: viewModel.scopeSummary,
                    inspectAction: requestScopeInspectionAction
                )
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
