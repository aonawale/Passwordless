import Vapor
import HTTP
import Cookies
import Foundation
import JWT

public final class SignUpMiddleware: Middleware {
    let identityKey: String

    public init(identityKey: String = "id") {
        self.identityKey = identityKey
    }

    public func respond(to request: HTTP.Request, chainingTo next: Responder) throws -> Response {
        let data = try Provider.verify(request: request)


        guard let reqJSON = request.json,
            let reqEmail: String = try? reqJSON.get(Provider.subject),
            reqEmail == data.sub else {
            throw Abort(.unauthorized, reason: "Unauthorized '\(Provider.subject)'")
        }

        let response = try next.respond(to: request)

        if response.status == .created {
            guard let resJSON = response.json,
                let id = resJSON[identityKey]?.string else {
                throw Abort(.internalServerError, reason: "\(identityKey) not found in response payload")
            }

            // token
            var json = JSON()
            try json.set("sub", JWTIDClaim(string: id).value)
            try json.set("iat", IssuedAtClaim(seconds: Seconds(Date().timeIntervalSince1970)).value)
            try json.set("exp", ExpirationTimeClaim.init(createTimestamp: {
                Seconds((Date() + Provider.tokenExp).timeIntervalSince1970)
            }).value)

            let newToken = try JWT(payload: json, signer: Provider.signer)
            try Provider.add(token: try newToken.createToken(), subject: data.sub, to: response)

            // clean up
            try Provider.cache.delete(data.sub)
            if Provider.sameDevice {
                response.cookies.remove(Cookie(name: "iss", value: ""))
            }
        }

        return response
    }
}
