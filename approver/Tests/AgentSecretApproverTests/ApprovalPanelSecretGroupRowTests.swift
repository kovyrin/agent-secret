@testable import AgentSecretApprover
import XCTest

#if canImport(AppKit) && canImport(SwiftUI)
    import AppKit
    import SwiftUI

    final class ApprovalPanelSecretGroupRowTests: XCTestCase {
        @MainActor
        func testExpandedSecretGroupRowAllocatesReadableListSpace() {
            let expandedListChromeAllowance: CGFloat = ApprovalPanelStyle.Metric.buttonHeight
            let expandedListMinimumGrowth: CGFloat =
                ApprovalPanelStyle.Metric.groupExpandedListMaxHeight / ApprovalPanelStyle.Metric.decisionButtonGapCount
            let expandedListMaximumGrowth: CGFloat =
                ApprovalPanelStyle.Metric.groupExpandedListMaxHeight + expandedListChromeAllowance
            let layoutProbeHeight: CGFloat =
                ApprovalPanelStyle.Metric.groupExpandedListMaxHeight * ApprovalPanelStyle.Metric.decisionButtonCount
            let layoutProbeWidth: CGFloat =
                ApprovalPanelStyle.Metric.cardWidth -
                ApprovalPanelStyle.Metric.cardHorizontalPadding * ApprovalPanelStyle.Metric.decisionButtonGapCount
            let secrets = [
                RequestedSecretRowViewModel(alias: "ANSIBLE_BECOME_PASSWORD", ref: "op://Jarvis/One/password"),
                RequestedSecretRowViewModel(alias: "BECOME_PASSWORD", ref: "op://Jarvis/Two/password"),
                RequestedSecretRowViewModel(alias: "GRAFANA_ADMIN_PASSWORD", ref: "op://Jarvis/Three/password"),
                RequestedSecretRowViewModel(alias: "SANDBOX_API_SECRET", ref: "op://Jarvis/Four/password"),
                RequestedSecretRowViewModel(alias: "POSTGRES_PASSWORD", ref: "op://Jarvis/Five/password"),
                RequestedSecretRowViewModel(alias: "CADDY_TOKEN", ref: "op://Jarvis/Six/password"),
                RequestedSecretRowViewModel(alias: "CF_API_TOKEN", ref: "op://Jarvis/Seven/password"),
                RequestedSecretRowViewModel(alias: "MQTT_PASSWORD", ref: "op://Jarvis/Eight/password"),
                RequestedSecretRowViewModel(alias: "HOME_ASSISTANT_TOKEN", ref: "op://Jarvis/Nine/password"),
                RequestedSecretRowViewModel(alias: "SYNCTHING_KEY", ref: "op://Jarvis/Ten/password"),
                RequestedSecretRowViewModel(alias: "ZWAVE_SECRET", ref: "op://Jarvis/Eleven/password")
            ]
            let group = SecretVaultGroupViewModel(vaultName: "Jarvis", secrets: secrets)
            let collapsedHeight = hostingHeight(
                for: ApprovalPanelSecretGroupRow(group: group, isExpanded: false) {
                    /* No decision action needed. */
                }
            )
            let expandedHeight = hostingHeight(
                for: ApprovalPanelSecretGroupRow(group: group, isExpanded: true) {
                    /* No decision action needed. */
                }
            )

            XCTAssertGreaterThan(expandedHeight, collapsedHeight + expandedListMinimumGrowth)
            XCTAssertLessThan(expandedHeight, collapsedHeight + expandedListMaximumGrowth)

            func hostingHeight(for view: some View) -> CGFloat {
                let host = NSHostingView(rootView: view)
                host.frame = NSRect(
                    origin: .zero,
                    size: NSSize(width: layoutProbeWidth, height: layoutProbeHeight)
                )
                host.layoutSubtreeIfNeeded()
                return host.fittingSize.height
            }
        }

        deinit {
            /* Required by SwiftLint. */
        }
    }
#endif
