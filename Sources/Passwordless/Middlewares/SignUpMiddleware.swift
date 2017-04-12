import Vapor
import HTTP
import VaporJWT
import Cookies
import Foundation

public final class SignUpMiddleware: Middleware {
    let identityKey: String

    public init(identityKey: String = "id") {
        self.identityKey = identityKey
    }

    public func respond(to request: HTTP.Request, chainingTo next: Responder) throws -> Response {
        let data = try Provider.verify(request: request)

        guard let reqEmail = request.json?[Provider.subject]?.string, reqEmail == data.sub else {
            throw Abort.custom(status: .unauthorized, message: "Unauthorized '\(Provider.subject)'")
        }

        let response = try next.respond(to: request)

        guard let id = response.json?[identityKey]?.string else {
            throw Abort.custom(status: .internalServerError, message: "\(identityKey) not found in response payload")
        }

        if response.status == .created {
            // token
            let payload = try Node(node: [
                identityKey: Node(JWTIDClaim(id)),
                "iat": Node(IssuedAtClaim(Seconds(Date().timeIntervalSince1970))),
                "exp": Node(ExpirationTimeClaim(Date() + Provider.tokenExp))
            ])
            let newToken = try JWT(payload: payload, signer: Provider.signer)
            Provider.add(token: try newToken.createToken(), to: response)

            // clean up
            try Provider.cache.delete(data.sub)
            if Provider.sameDevice {
                response.cookies.remove(Cookie(name: "iss", value: ""))
            }
        }

        return response
    }
}
