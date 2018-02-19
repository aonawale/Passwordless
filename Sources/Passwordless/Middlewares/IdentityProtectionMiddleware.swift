import Vapor
import HTTP
import JWT
import Cookies
import AuthProvider

public final class IdentityProtectionMiddleware<T: Parameterizable>: Middleware {
    let param: String
    let identityKey: String

    public init(param: String = T.uniqueSlug, identityKey: String = "sub") {
        self.param = param
        self.identityKey = identityKey
    }

    public func respond(to request: HTTP.Request, chainingTo next: Responder) throws -> Response {
        guard let bearer = request.auth.header?.bearer else {
            throw AuthenticationError.noAuthorizationHeader
        }

        guard let token = try? JWT(token: bearer.string),
            let id = token.payload[identityKey]?.string else {
            throw AuthenticationError.invalidBearerAuthorization
        }

        do {
            _ = try token.verifySignature(using: Provider.signer)
        } catch {
            throw Abort(.unauthorized, reason: Status.unauthorized.reasonPhrase)
        }

        guard id == request.parameters[param]?.string else {
            throw Abort(.unauthorized, reason: Status.unauthorized.reasonPhrase)
        }

        return try next.respond(to: request)
    }
}
