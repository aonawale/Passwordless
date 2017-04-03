import Vapor
import HTTP
import VaporJWT
import Cookies
import Auth

public final class EmailAuthMiddleware: Middleware {
    public init() {}

    public func respond(to request: HTTP.Request, chainingTo next: Responder) throws -> Response {
        guard let email = request.json?[Provider.subject]?.string else {
            throw Abort.custom(status: .badRequest, message: "`\(Provider.subject)` is required")
        }
        let issuer = Provider.issuer(age: 60 * 5)
        let token = try Provider.tokenString(for: email, issuer: issuer.value, expires: 60)
        request.storage["token"] = token

        let response = try next.respond(to: request)

        if response.status == .ok {
            try Provider.cache.set(email, token)

            if Provider.sameDevice {
                response.cookies.insert(issuer)
            }
        }

        return response
    }
}
