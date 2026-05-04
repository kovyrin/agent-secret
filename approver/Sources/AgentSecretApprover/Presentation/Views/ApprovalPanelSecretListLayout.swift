import Foundation

#if canImport(SwiftUI)
    import SwiftUI

    enum ApprovalPanelSecretListLayout {
        private typealias Metric = ApprovalPanelStyle.Metric

        static func aliasColumnWidth(for aliases: [String]) -> CGFloat {
            let longestAliasLength = aliases.map(\.count).max() ?? 0
            let preferredWidth = CGFloat(longestAliasLength) * Metric.secretListAliasCharacterWidth +
                Metric.secretListAliasHorizontalAllowance
            return min(
                max(preferredWidth, Metric.secretListAliasMinimumWidth),
                Metric.secretListAliasMaximumWidth
            )
        }
    }
#endif
