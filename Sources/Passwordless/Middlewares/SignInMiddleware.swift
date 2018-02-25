import Vapor
import HTTP
import JWT
import Cookies
import TurnstileCrypto
import Crypto
import Foundation

public final class SignInMiddleware: Middleware {
    let identityKey: String

    public init(identityKey: String = "id") {
        self.identityKey = identityKey
    }

    public func respond(to request: HTTP.Request, chainingTo next: Responder) throws -> Response {
        let (_, subject, _) = try Provider.verify(request: request)

        request.storage[Provider.subject] = subject

        let response = try next.respond(to: request)

        guard 200..<300 ~= response.status.statusCode else {
            let iss = TurnstileCrypto.URandom().secureToken
            let issuer = Provider.issuer(age: Provider.tempTokenExp, issuer: iss)
            let token = try Provider.tempToken(for: subject, issuer: iss)
            try Provider.cache.set(subject, token)
            response.cookies.insert(issuer)
            try Provider.add(token: token, subject: subject, to: response)
            return response
        }

        guard let id = response.json?[identityKey]?.string else {
            throw Abort(.internalServerError, reason: "\(identityKey) not found in response payload")
        }

        // clean up
        try Provider.cache.delete(subject)

        // token
        var json = JSON()
        try json.set("sub", JWTIDClaim(string: id).value)
        try json.set("iat", IssuedAtClaim(seconds: Seconds(Date().timeIntervalSince1970)).value)
        try json.set("exp", ExpirationTimeClaim.init(createTimestamp: {
            Seconds((Date() + Provider.tokenExp).timeIntervalSince1970)
        }).value)

        let newToken = try JWT(payload: json, signer: Provider.signer)
        try Provider.add(token: try newToken.createToken(), subject: subject, to: response)

        return response
    }
}
