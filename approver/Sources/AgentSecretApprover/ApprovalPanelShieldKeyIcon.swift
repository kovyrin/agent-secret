import Foundation

#if canImport(SwiftUI)
    import SwiftUI

    struct ApprovalPanelShieldKeyIcon: View {
        private typealias Metric = ApprovalPanelStyle.Metric

        var body: some View {
            ZStack {
                Image(systemName: "shield")
                    .font(.system(size: Metric.headerIconShieldSize, weight: .regular))
                    .accessibilityHidden(true)
                Image(systemName: "key")
                    .font(.system(size: Metric.headerIconKeySize, weight: .semibold))
                    .offset(y: Metric.headerIconKeyOffset)
                    .accessibilityHidden(true)
            }
            .foregroundStyle(Color.green)
            .accessibilityLabel("Secret access request")
        }
    }
#endif
