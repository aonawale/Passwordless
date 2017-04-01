import Vapor
import HTTP
import VaporJWT
import Cookies

public final class SignInMiddleware: Middleware {
    public init() {}
    
    public func respond(to request: HTTP.Request, chainingTo next: Responder) throws -> Response {
        let data = try Passwordless.verify(request: request)
        
        request.storage["email"] = data.sub
        
        let response = try next.respond(to: request)
        
        guard response.status != .notFound else {
            let token = try Passwordless.tokenString(for: data.sub, expires: 60 * 5)
            try Passwordless.cache.set(data.sub, token)
            response.cookies.insert(Passwordless.issuer(age: 60 * 5))
            response.headers.Authorization = token
            throw Abort.notFound
        }
        
        let newToken = try Passwordless.tokenString(for: data.sub, expires: 60 * 5)
        
        try Passwordless.cache.set(data.sub, newToken)
        
        response.headers.Authorization = newToken
        
        return response
    }
}
