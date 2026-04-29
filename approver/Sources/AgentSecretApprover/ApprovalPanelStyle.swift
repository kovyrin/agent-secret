import Foundation

#if canImport(SwiftUI)
    import SwiftUI

    enum ApprovalPanelStyle {
        enum Metric {
            static let aliasSpacing: CGFloat = 6
            static let bodyFontSize: CGFloat = 13
            static let borderWidth: CGFloat = 1
            static let buttonHeight: CGFloat = 58
            static let buttonHorizontalPadding: CGFloat = 12
            static let buttonIconSize: CGFloat = 20
            static let buttonShadowOpacity: Double = 0.16
            static let buttonShadowRadius: CGFloat = 5
            static let buttonShadowYOffset: CGFloat = 3
            static let buttonSpacing: CGFloat = 12
            static let buttonSubtitleFontSize: CGFloat = 11
            static let buttonTitleFontSize: CGFloat = 13
            static let buttonTitleLineLimit: Int = 2
            static let cardCornerRadius: CGFloat = 20
            static let cardHorizontalPadding: CGFloat = 30
            static let cardOpacity: Double = 0.98
            static let cardShadowOpacity: Double = 0.22
            static let cardShadowRadius: CGFloat = 18
            static let cardShadowYOffset: CGFloat = 10
            static let cardVerticalPadding: CGFloat = 24
            static let cardWidth: CGFloat = 780
            static let cautionBlue: Double = 0.04
            static let cautionBorderOpacity: Double = 0.30
            static let cautionCornerRadius: CGFloat = 12
            static let cautionGreen: Double = 0.22
            static let cautionIconSize: CGFloat = 18
            static let cautionPadding: CGFloat = 10
            static let cautionPanelOpacity: Double = 0.08
            static let cautionRed: Double = 0.38
            static let cautionSpacing: CGFloat = 10
            static let compactSecretLimit: Int = 5
            static let contextRowSpacing: CGFloat = 10
            static let contextTitleFontSize: CGFloat = 13
            static let contextValueFontSize: CGFloat = 12
            static let decisionButtonCount: CGFloat = 3
            static let decisionButtonGapCount: CGFloat = 2
            static let decisionButtonWidth: CGFloat = (
                cardWidth - (cardHorizontalPadding * horizontalEdgeCount) - (buttonSpacing * decisionButtonGapCount)
            ) / decisionButtonCount
            static let detailLabelSpacing: CGFloat = 2
            static let detailLeadingPadding: CGFloat = 22
            static let detailSpacing: CGFloat = 5
            static let detailSubtitleFontSize: CGFloat = 12
            static let detailTitleFontSize: CGFloat = 14
            static let detailTopPadding: CGFloat = 5
            static let footerIconSize: CGFloat = 18
            static let footerSpacing: CGFloat = 12
            static let greenBorderOpacity: Double = 0.22
            static let greenPanelOpacity: Double = 0.05
            static let groupAliasFontSize: CGFloat = 11
            static let groupChevronFontSize: CGFloat = 10
            static let groupCountFontSize: CGFloat = 11
            static let groupIconCharacterCount: Int = 1
            static let groupIconFontSize: CGFloat = 12
            static let groupIconSize: CGFloat = 28
            static let groupListSpacing: CGFloat = 6
            static let groupRowSpacing: CGFloat = 10
            static let groupRowVerticalPadding: CGFloat = 6
            static let groupTitleFontSize: CGFloat = 13
            static let headerIconKeyOffset: CGFloat = 3
            static let headerIconKeySize: CGFloat = 20
            static let headerIconShieldSize: CGFloat = 44
            static let headerIconSize: CGFloat = 52
            static let headerSpacing: CGFloat = 18
            static let horizontalEdgeCount: CGFloat = 2
            static let iconBoxCornerRadius: CGFloat = 9
            static let iconBoxFillOpacity: Double = 0.55
            static let iconBoxSize: CGFloat = 34
            static let iconFontSize: CGFloat = 16
            static let inlineFontSize: CGFloat = 15
            static let inlineSpacing: CGFloat = 8
            static let inspectorHeight: CGFloat = 420
            static let inspectorWidth: CGFloat = 760
            static let minimumScaleFactor: CGFloat = 0.80
            static let outerPadding: CGFloat = 14
            static let panelCornerRadius: CGFloat = 12
            static let pillCornerRadius: CGFloat = 8
            static let pillFontSize: CGFloat = 13
            static let pillHorizontalPadding: CGFloat = 8
            static let pillVerticalPadding: CGFloat = 4
            static let primaryBorderOpacity: Double = 0.45
            static let promptFontSize: CGFloat = 21
            static let promptSpacing: CGFloat = 8
            static let refLayoutPriority: Double = 1
            static let rowTextSpacing: CGFloat = 3
            static let rowSpacing: CGFloat = 12
            static let secondaryBorderOpacity: Double = 0.25
            static let secretListAliasFontSize: CGFloat = 14
            static let secretListAliasWidth: CGFloat = 130
            static let secretListIconFontSize: CGFloat = 12
            static let secretListIconSize: CGFloat = 26
            static let secretListRefFontSize: CGFloat = 11
            static let secretListRowSpacing: CGFloat = 10
            static let secretListSpacing: CGFloat = 8
            static let secretCardSpacing: CGFloat = 8
            static let secretIconSize: CGFloat = 42
            static let secretPanelPadding: CGFloat = 14
            static let sectionLabelFontSize: CGFloat = 14
            static let sectionSpacing: CGFloat = 12
            static let singleLineLimit: Int = 1
            static let singleSecretCount: Int = 1
            static let subtleBorderOpacity: Double = 0.18
            static let subtleFillOpacity: Double = 0.06
            static let titleFontSize: CGFloat = 23
            static let twoLineLimit: Int = 2
            static let zeroOffset: CGFloat = 0
        }

        enum Palette {
            static let cautionText = Color(
                red: Metric.cautionRed,
                green: Metric.cautionGreen,
                blue: Metric.cautionBlue
            )
        }
    }
#endif
