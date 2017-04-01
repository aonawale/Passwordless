import Vapor
import HTTP
import VaporJWT
import Cookies

public final class AuthorizationMiddleware: Middleware {
    public init() {}
    
    public func respond(to request: HTTP.Request, chainingTo next: Responder) throws -> Response {
        guard let bearer = request.headers.Bearer else {
            throw Abort.custom(status: .badRequest, message: "Authorization Bearer is required.")
        }
        
        guard let token = try? JWT(token: bearer),
            let _ = try? token.verifySignatureWith(Passwordless.signer),
            let subject = token.payload["sub"]?.string else {
                throw Abort.custom(status: .unauthorized, message: "Invalid Authorization token. The token cannot be verified.")
        }
        
        guard let _ = try Passwordless.cache.get(subject)?.string else {
            try? Passwordless.cache.delete(subject)
            throw Abort.custom(status: .unauthorized, message: "Invalid Authorization token. The token cannot be verified.")
        }
        
        return try next.respond(to: request)
    }
}
