import Vapor
import HTTP
import VaporJWT
import Cookies
import TurnstileCrypto
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
            let issuer = Provider.issuer(age: 60 * 5, issuer: iss)
            let token = try Provider.tempToken(for: subject, issuer: iss)
            try Provider.cache.set(subject, token)
            response.cookies.insert(issuer)
            Provider.add(token: token, to: response)
            return response
        }

        guard let id = response.json?[identityKey]?.string else {
            throw Abort.custom(status: .internalServerError, message: "\(identityKey) not found in response payload")
        }

        // clean up
        try Provider.cache.delete(subject)

        // token
        let payload = try Node(node: [
            identityKey: Node(JWTIDClaim(id)),
            "iat": Node(IssuedAtClaim(Seconds(Date().timeIntervalSince1970))),
            "exp": Node(ExpirationTimeClaim(Date() + Provider.tokenExp))
        ])
        let newToken = try JWT(payload: payload, signer: Provider.signer)
        Provider.add(token: try newToken.createToken(), to: response)

        return response
    }
}
