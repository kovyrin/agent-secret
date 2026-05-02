enum ApproverAppError: Error, CustomStringConvertible {
    case missingValue(String)
    case unsupportedArgument(String)

    var description: String {
        switch self {
        case let .missingValue(flag):
            "missing value for \(flag)"

        case let .unsupportedArgument(argument):
            "unsupported argument \(argument)"
        }
    }
}
