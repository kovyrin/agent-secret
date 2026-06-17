import Foundation

public struct SessionBindingInfo: Codable, Equatable, Sendable {
    private enum CodingKeys: String, CodingKey {
        case mode
        case ancestorDepth = "ancestor_depth"
        case ancestorName = "ancestor_name"
        case ancestorNames = "ancestor_names"
        case boundProcess = "bound_process"
        case creatorProcess = "creator_process"
    }

    public var mode: String
    public var ancestorDepth: Int?
    public var ancestorName: String?
    public var ancestorNames: [String]
    public var boundProcess: SessionBindingProcess
    public var creatorProcess: SessionBindingProcess

    public init(
        mode: String,
        boundProcess: SessionBindingProcess,
        creatorProcess: SessionBindingProcess,
        ancestorDepth: Int? = nil,
        ancestorName: String? = nil,
        ancestorNames: [String] = []
    ) {
        self.mode = mode
        self.ancestorDepth = ancestorDepth
        self.ancestorName = ancestorName
        self.ancestorNames = ancestorNames
        self.boundProcess = boundProcess
        self.creatorProcess = creatorProcess
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        mode = try container.decode(String.self, forKey: .mode)
        ancestorDepth = try container.decodeIfPresent(Int.self, forKey: .ancestorDepth)
        ancestorName = try container.decodeIfPresent(String.self, forKey: .ancestorName)
        ancestorNames = try container.decodeIfPresent([String].self, forKey: .ancestorNames) ?? []
        boundProcess = try container.decode(SessionBindingProcess.self, forKey: .boundProcess)
        creatorProcess = try container.decode(SessionBindingProcess.self, forKey: .creatorProcess)
    }
}
