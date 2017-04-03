import Vapor
import HTTP
import VaporJWT
import Cookies

public final class SignUpMiddleware: Middleware {
    public init() {}

    public func respond(to request: HTTP.Request, chainingTo next: Responder) throws -> Response {
        let data = try Provider.verify(request: request)

        guard let reqEmail = request.json?[Provider.subject]?.string, reqEmail == data.sub else {
            throw Abort.custom(status: .conflict, message: "'\(Provider.subject)' mismatch")
        }

        let response = try next.respond(to: request)

        if response.status == .created {
            // token
            let newToken = try Provider.tokenString(for: data.sub, expires: 60 * 5)
            response.headers["token"] = newToken

            // clean up
            try Provider.cache.delete(data.sub)
            if Provider.sameDevice {
                response.cookies.remove(Cookie(name: "iss", value: ""))
            }
        }

        return response
    }
}
