import Vapor
import HTTP
import VaporJWT
import Cookies

public final class EmailAuthMiddleware: Middleware {
    public init() {}
    
    public func respond(to request: HTTP.Request, chainingTo next: Responder) throws -> Response {
        guard let email = request.json?["email"]?.string else {
            throw Abort.custom(status: .badRequest, message: "Email is required")
        }
        let issuer = Passwordless.issuer(age: 60 * 5)
        let token = try Passwordless.tokenString(for: email, issuer: issuer.value, expires: 60)
        request.storage["token"] = token
        
        let response = try next.respond(to: request)
        
        if response.status == .ok {
            try Passwordless.cache.set(email, token)
            response.cookies.insert(issuer)
        }
        
        return response
    }
}
