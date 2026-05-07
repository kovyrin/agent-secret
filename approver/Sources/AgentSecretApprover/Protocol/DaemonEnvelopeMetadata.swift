import Foundation

protocol DaemonEnvelopeMetadata {
    var nonce: String? { get }
    var requestID: String? { get }
    var type: DaemonMessageType { get }
    var version: Int { get }
}
