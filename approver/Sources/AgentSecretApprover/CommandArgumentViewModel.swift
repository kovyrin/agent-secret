import Foundation

struct CommandArgumentViewModel: Equatable {
    private enum ScalarCode {
        static let backspace: UInt32 = 8
        static let backslash: UInt32 = 92
        static let bell: UInt32 = 7
        static let carriageReturn: UInt32 = 13
        static let controlDelete: UInt32 = 127
        static let escape: UInt32 = 27
        static let horizontalTab: UInt32 = 9
        static let lineFeed: UInt32 = 10
        static let printableHighStart: UInt32 = 128
        static let printablePrefixEnd: UInt32 = 38
        static let printablePrefixStart: UInt32 = 32
        static let printableSuffixEnd: UInt32 = 126
        static let printableSuffixStart: UInt32 = 93
        static let printableWithoutBackslashEnd: UInt32 = 91
        static let printableWithoutBackslashStart: UInt32 = 40
        static let singleQuote: UInt32 = 39
    }

    let index: Int
    let value: String
    let escaped: String
    let needsInspector: Bool

    var inspectorLine: String {
        "argv[\(index)]: \(escaped)"
    }

    init(index: Int, value: String) {
        self.index = index
        self.value = value
        escaped = Self.shellEscaped(value)
        needsInspector = Self.needsInspector(value)
    }

    private static func shellEscaped(_ value: String) -> String {
        if value.isEmpty {
            return "''"
        }
        if value.unicodeScalars.contains(where: { scalar in Self.isASCIIControlCharacter(scalar) }) {
            return "$'\(ansiCEscaped(value))'"
        }
        return "'\(value.replacingOccurrences(of: "'", with: "'\\''"))'"
    }

    private static func ansiCEscaped(_ value: String) -> String {
        let escaped = value.unicodeScalars.map { scalar -> String in
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

            case ScalarCode.escape:
                return "\\e"

            case ScalarCode.singleQuote:
                return "\\'"

            case ScalarCode.backslash:
                return "\\\\"

            default:
                if Self.isPrintableLiteral(scalar) {
                    return String(scalar)
                }
                return String(format: "\\x%02X", scalar.value)
            }
        }
        return escaped.joined()
    }

    private static func needsInspector(_ value: String) -> Bool {
        if value.isEmpty || value.hasPrefix("-") {
            return true
        }
        let shellMetacharacters = CharacterSet(charactersIn: "|&;<>()$`\\\"'*!?[]{}")
        return value.rangeOfCharacter(from: .whitespacesAndNewlines) != nil ||
            value.rangeOfCharacter(from: .controlCharacters) != nil ||
            value.rangeOfCharacter(from: shellMetacharacters) != nil
    }

    private static func isASCIIControlCharacter(_ scalar: Unicode.Scalar) -> Bool {
        scalar.value < ScalarCode.printablePrefixStart || scalar.value == ScalarCode.controlDelete
    }

    private static func isPrintableLiteral(_ scalar: Unicode.Scalar) -> Bool {
        let value = scalar.value
        return (ScalarCode.printablePrefixStart ... ScalarCode.printablePrefixEnd).contains(value) ||
            (ScalarCode.printableWithoutBackslashStart ... ScalarCode.printableWithoutBackslashEnd).contains(value) ||
            (ScalarCode.printableSuffixStart ... ScalarCode.printableSuffixEnd).contains(value) ||
            value >= ScalarCode.printableHighStart
    }
}
