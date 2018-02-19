import Vapor
import HTTP
import Cookies
import AuthProvider
import JWT

public final class AuthorizationMiddleware: Middleware {
    public init() {}

    public func respond(to request: HTTP.Request, chainingTo next: Responder) throws -> Response {
        guard let accessToken = request.auth.header?.bearer else {
            throw AuthenticationError.noAuthorizationHeader
        }

        guard let token = try? JWT(token: accessToken.string) else {
            throw AuthenticationError.invalidBearerAuthorization
        }

        do {
            try token.verifySignature(using: Provider.signer)
        } catch {
            throw Abort(.unauthorized, reason: Status.unauthorized.reasonPhrase)
        }

        return try next.respond(to: request)
    }
}
