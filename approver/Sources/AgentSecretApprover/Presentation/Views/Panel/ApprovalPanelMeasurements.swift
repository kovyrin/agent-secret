import Foundation

#if canImport(SwiftUI)
    import SwiftUI

    enum ApprovalPanelMeasurements {
        struct Value: Equatable {
            var scrollContentHeight: CGFloat = 0
            var pinnedContentHeight: CGFloat = 0
        }

        struct Key: PreferenceKey {
            static var defaultValue: Value {
                Value()
            }

            static func reduce(value: inout Value, nextValue: () -> Value) {
                let next = nextValue()
                value.scrollContentHeight = max(value.scrollContentHeight, next.scrollContentHeight)
                value.pinnedContentHeight = max(value.pinnedContentHeight, next.pinnedContentHeight)
            }
        }
    }
#endif
