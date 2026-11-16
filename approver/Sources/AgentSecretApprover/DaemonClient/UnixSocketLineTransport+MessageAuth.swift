import Foundation

#if canImport(Darwin)
    extension UnixSocketLineTransport {
        func beginMessageAuth() throws {
            try writeLine(Data(#"{"type":"auth.hello","version":1}"#.utf8))
            let data = try readLine()
            let response: AuthHelloReply
            do {
                response = try JSONDecoder().decode(AuthHelloReply.self, from: data)
            } catch {
                throw SocketDaemonClientError.invalidResponse("invalid request authentication response")
            }
            if response.type == .error, response.payload?.code == .badType {
                throw SocketDaemonClientError.daemonError(.badType)
            }
            guard response.type == .okResponse, response.version == 1 else {
                throw SocketDaemonClientError.invalidResponse("invalid request authentication response")
            }
            guard let port = response.payload?.port, !port.isEmpty else {
                throw SocketDaemonClientError.invalidResponse("invalid request authentication response")
            }
            authPortName = port
        }
    }
#endif
