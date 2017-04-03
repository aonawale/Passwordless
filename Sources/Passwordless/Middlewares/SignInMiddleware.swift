import Vapor
import HTTP
import VaporJWT
import Cookies

public final class SignInMiddleware: Middleware {
    public init() {}

    public func respond(to request: HTTP.Request, chainingTo next: Responder) throws -> Response {
        let data = try Provider.verify(request: request)

        request.storage[Provider.subject] = data.sub

        let response = try next.respond(to: request)

        guard response.status != .notFound else {
            let token = try Provider.tokenString(for: data.sub, expires: 60 * 5)
            try Provider.cache.set(data.sub, token)
            response.cookies.insert(Provider.issuer(age: 60 * 5))
            response.headers["token"] = token
            throw Abort.notFound
        }

        // clean up
        try Provider.cache.delete(data.sub)

        // token
        let newToken = try Provider.tokenString(for: data.sub, expires: 60 * 5)
        response.headers["token"] = newToken

        return response
    }
}
