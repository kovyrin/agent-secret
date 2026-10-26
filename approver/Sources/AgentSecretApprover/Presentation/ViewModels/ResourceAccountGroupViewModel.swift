import Foundation

struct ResourceAccountGroupViewModel: Equatable {
    let identity: ResourceScopeIdentity
    var resources: [RequestedResourceRowViewModel]

    static func groups(_ resources: [RequestedResource]) -> [Self] {
        var groups: [Self] = []
        for resource in resources {
            let identity = ResourceScopeIdentity(resource)
            let row = RequestedResourceRowViewModel(resource: resource)
            if let index = groups.firstIndex(where: { $0.identity == identity }) {
                groups[index].resources.append(row)
            } else {
                groups.append(Self(identity: identity, resources: [row]))
            }
        }
        return groups
    }
}
