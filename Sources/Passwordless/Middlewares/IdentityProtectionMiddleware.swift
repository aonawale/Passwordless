import Vapor
import HTTP
import VaporJWT
import Cookies
import Auth

public final class IdentityProtectionMiddleware: Middleware {
    let param: String
    let identityKey: String

    // w0 id used internally by Vapor when you call .get, .post, etc on builder
    public init(param: String = "w0", identityKey: String = "id") {
        self.param = param
        self.identityKey = identityKey
    }

    public func respond(to request: HTTP.Request, chainingTo next: Responder) throws -> Response {
        guard let bearer = request.auth.header?.bearer else {
            throw AuthError.noAuthorizationHeader
        }

        guard let token = try? JWT(token: bearer.string),
            let id = token.payload[identityKey]?.string else {
            throw AuthError.invalidBearerAuthorization
        }

        do {
            _ = try token.verifySignatureWith(Provider.signer)
        } catch {
            throw Abort.custom(status: .unauthorized, message: Status.unauthorized.reasonPhrase)
        }

        guard id == request.parameters[param]?.string else {
            throw Abort.custom(status: .unauthorized, message: Status.unauthorized.reasonPhrase)
        }

        return try next.respond(to: request)
    }
}
