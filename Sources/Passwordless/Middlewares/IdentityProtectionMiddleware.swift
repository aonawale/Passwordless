import Vapor
import HTTP
import VaporJWT
import Cookies
import Auth

public final class IdentityProtetionMiddleware<T: TokenAuthenticatable>: Middleware {
    public init() {}

    public func respond(to request: HTTP.Request, chainingTo next: Responder) throws -> Response {
        guard let accessToken = request.auth.header?.bearer else {
            throw AuthError.invalidBearerAuthorization
        }

        guard let token = try? JWT(token: accessToken.string),
            let _ = try? token.verifySignatureWith(Provider.signer) else {
            throw AuthError.invalidBearerAuthorization
        }

        do {
            try T.authenticate(accessToken)
        } catch {
            throw AuthError.invalidBearerAuthorization
        }

        return try next.respond(to: request)
    }
}
