import Foundation

public struct SessionBindingInfo: Codable, Equatable, Sendable {
    private enum CodingKeys: String, CodingKey {
        case mode
        case ancestorDepth = "ancestor_depth"
        case boundProcess = "bound_process"
        case creatorProcess = "creator_process"
    }

    public var mode: String
    public var ancestorDepth: Int?
    public var boundProcess: SessionBindingProcess
    public var creatorProcess: SessionBindingProcess

    public init(
        mode: String,
        boundProcess: SessionBindingProcess,
        creatorProcess: SessionBindingProcess,
        ancestorDepth: Int? = nil
    ) {
        self.mode = mode
        self.ancestorDepth = ancestorDepth
        self.boundProcess = boundProcess
        self.creatorProcess = creatorProcess
    }
}
