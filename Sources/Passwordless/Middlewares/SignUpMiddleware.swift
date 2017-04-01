import Vapor
import HTTP
import VaporJWT
import Cookies

public final class SignUpMiddleware: Middleware {
    public init() {}
    
    public func respond(to request: HTTP.Request, chainingTo next: Responder) throws -> Response {
        let data = try Passwordless.verify(request: request)
        
        guard let reqEmail = request.json?["email"]?.string, reqEmail == data.sub else {
            throw Abort.custom(status: .conflict, message: "Email mismatch")
        }
        
        let response = try next.respond(to: request)
        
        if response.status == .created {
            let newToken = try Passwordless.tokenString(for: data.sub, expires: 60 * 5)
            
            response.headers.Authorization = newToken
            
            try Passwordless.cache.set(data.sub, newToken)
            
            response.cookies.remove(Cookie(name: "iss", value: ""))
        }
        
        return response
    }
}
