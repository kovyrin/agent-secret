import Foundation

public struct SessionBindingProcess: Codable, Equatable, Sendable {
    private enum CodingKeys: String, CodingKey {
        case pid
        case parentPID = "parent_pid"
        case name
        case path
    }

    public var pid: Int
    public var parentPID: Int?
    public var name: String
    public var path: String

    public init(pid: Int, name: String, path: String, parentPID: Int? = nil) {
        self.pid = pid
        self.parentPID = parentPID
        self.name = name
        self.path = path
    }
}
