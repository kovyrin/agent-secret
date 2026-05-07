import Foundation

#if canImport(SwiftUI)
    import SwiftUI

    enum ApprovalPanelResourceListLayout {
        private typealias Metric = ApprovalPanelStyle.Metric

        static func aliasColumnWidth(for aliases: [String]) -> CGFloat {
            let longestAliasLength = aliases.map(\.count).max() ?? 0
            let preferredWidth = CGFloat(longestAliasLength) * Metric.resourceListAliasCharacterWidth +
                Metric.resourceListAliasHorizontalAllowance
            return min(
                max(preferredWidth, Metric.resourceListAliasMinimumWidth),
                Metric.resourceListAliasMaximumWidth
            )
        }
    }
#endif
