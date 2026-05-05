import Foundation

#if canImport(SwiftUI)
    import SwiftUI

    struct ApprovalPanelSecretReferenceText: View {
        private typealias Palette = ApprovalPanelStyle.Palette

        let segments: [RequestedSecretReferenceSegment]
        let fontSize: CGFloat
        let lineLimit: Int?

        var body: some View {
            styledText
                .lineLimit(lineLimit)
        }

        private var styledText: Text {
            segments.reduce(Text("")) { text, segment in
                text + styledSegment(segment)
            }
        }

        private func styledSegment(_ segment: RequestedSecretReferenceSegment) -> Text {
            Text(segment.text)
                .font(.system(
                    size: fontSize,
                    weight: segment.isEmphasized ? .bold : .regular,
                    design: .monospaced
                ))
                .foregroundColor(segment.isEmphasized ? Palette.secretReferenceEmphasis : Palette.secretReference)
        }
    }
#endif
