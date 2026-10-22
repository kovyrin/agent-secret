import Foundation

/// Shared by the production panel, initial measurement, and sizing proofs.
enum ApprovalPanelLayout {
    static let preferredWidth: CGFloat = 908
    static let preferredHeight: CGFloat = 648
    static let preferredSize = CGSize(width: preferredWidth, height: preferredHeight)
    static let outerPadding: CGFloat = 14
    static let cornerRadius: CGFloat = 16
    static let contextPadding: CGFloat = 26
    static let sidebarPadding: CGFloat = 22
    static let sectionSpacing: CGFloat = 18
    static let sidebarWidth: CGFloat = 340
    static let twoColumnMinimumWidth: CGFloat = 800
    static let barAnimationDuration: TimeInterval = 0.2
    static let screenMargin: CGFloat = 32
    static let tightSpacing: CGFloat = 2
    static let labelSpacing: CGFloat = 3
    static let smallSpacing: CGFloat = 4
    static let detailSpacing: CGFloat = 6
    static let compactSpacing: CGFloat = 8
    static let warningCornerRadius: CGFloat = 9
    static let standardSpacing: CGFloat = 10
    static let captionFontSize: CGFloat = 11
    static let rowSpacing: CGFloat = 12
    static let bodyFontSize: CGFloat = 13
    static let labelFontSize: CGFloat = 14
    static let headingFontSize: CGFloat = 16
    static let titleFontSize: CGFloat = 21
    static let clockWidth: CGFloat = 38
    static let primaryButtonHeight: CGFloat = 42
    static let factLabelWidth: CGFloat = 64
    static let warningFillOpacity: Double = 0.10
    static let warningBorderOpacity: Double = 0.35
    static let mutedOpacity: Double = 0.4
}
