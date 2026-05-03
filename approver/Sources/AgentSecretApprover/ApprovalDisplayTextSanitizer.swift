import Foundation

enum ApprovalDisplayTextSanitizer {
    private enum ScalarCode {
        static let backspace: UInt32 = 8
        static let bell: UInt32 = 7
        static let carriageReturn: UInt32 = 13
        static let controlDelete: UInt32 = 127
        static let horizontalTab: UInt32 = 9
        static let lineFeed: UInt32 = 10
        static let maxByteEscapeScalar: UInt32 = 0xFF
        static let maxFourDigitEscapeScalar: UInt32 = 0xFFFF
        static let printablePrefixStart: UInt32 = 32
    }

    static func sanitize(_ value: String) -> String {
        value.unicodeScalars.map(sanitizedScalar).joined()
    }

    private static func sanitizedScalar(_ scalar: Unicode.Scalar) -> String {
        switch scalar.value {
        case ScalarCode.bell:
            return "\\a"

        case ScalarCode.backspace:
            return "\\b"

        case ScalarCode.horizontalTab:
            return "\\t"

        case ScalarCode.lineFeed:
            return "\\n"

        case ScalarCode.carriageReturn:
            return "\\r"

        default:
            if shouldEscape(scalar) {
                return unicodeEscape(scalar)
            }
            return String(scalar)
        }
    }

    private static func shouldEscape(_ scalar: Unicode.Scalar) -> Bool {
        if scalar.value < ScalarCode.printablePrefixStart || scalar.value == ScalarCode.controlDelete {
            return true
        }
        return switch scalar.properties.generalCategory {
        case .control, .format, .lineSeparator, .paragraphSeparator, .privateUse, .surrogate, .unassigned:
            true

        default:
            false
        }
    }

    private static func unicodeEscape(_ scalar: Unicode.Scalar) -> String {
        if scalar.value <= ScalarCode.maxByteEscapeScalar {
            return String(format: "\\x%02X", scalar.value)
        }
        if scalar.value <= ScalarCode.maxFourDigitEscapeScalar {
            return String(format: "\\u%04X", scalar.value)
        }
        return String(format: "\\U%08X", scalar.value)
    }
}
