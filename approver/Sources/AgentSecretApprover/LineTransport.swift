import Foundation

protocol LineTransport {
    func readLine() throws -> Data
    func writeLine(_ data: Data) throws
}
