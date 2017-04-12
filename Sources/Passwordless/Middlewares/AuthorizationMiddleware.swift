import Vapor
import HTTP
import VaporJWT
import Cookies
import Auth

public final class AuthorizationMiddleware: Middleware {
    public init() {}

    public func respond(to request: HTTP.Request, chainingTo next: Responder) throws -> Response {
        guard let accessToken = request.auth.header?.bearer else {
            throw AuthError.noAuthorizationHeader
        }

        guard let token = try? JWT(token: accessToken.string) else {
            throw AuthError.invalidBearerAuthorization
        }

        do {
            _ = try token.verifySignatureWith(Provider.signer)
        } catch {
            throw Abort.custom(status: .unauthorized, message: Status.unauthorized.reasonPhrase)
        }

        return try next.respond(to: request)
    }
}
