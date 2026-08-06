import Foundation

#if canImport(SwiftUI)
    import SwiftUI

    enum ApprovalPanelReasonMeasurements {
        struct Value: Equatable {
            var collapsedHeight: CGFloat = 0
            var fullHeight: CGFloat = 0
        }

        struct Key: PreferenceKey {
            static var defaultValue: Value {
                Value()
            }

            static func reduce(value: inout Value, nextValue: () -> Value) {
                let next = nextValue()
                value.collapsedHeight = max(value.collapsedHeight, next.collapsedHeight)
                value.fullHeight = max(value.fullHeight, next.fullHeight)
            }
        }
    }
#endif
