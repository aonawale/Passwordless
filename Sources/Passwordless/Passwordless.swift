import Vapor
import HTTP
import VaporJWT
import Foundation
import TurnstileCrypto
import Cache
import Cookies

public final class Passwordless {
    
    public typealias TokenPayload = (token: JWT, sub: String, iss: String)
    
    static var cache: CacheProtocol!
    static var signer: HMACSigner!
    
    enum Key: String {
        case subject
        case issuer
        case expiry
    }
    
    static func token(for subject: String, issuer: String = TurnstileCrypto.URandom().secureToken, expires: Date) throws -> JWT {
        let payload = try Node(node: [
            "iss": issuer,
            "sub": subject,
            "exp": Node(ExpirationTimeClaim(expires))
        ])
        return try JWT(payload: payload, signer: Passwordless.signer)
    }
    
    static func tokenString(for subject: String, issuer: String = TurnstileCrypto.URandom().secureToken, expires: Date) throws -> String {
        return try Passwordless.token(for: subject, issuer: issuer, expires: expires).createToken()
    }
    
    static func tokenString(for subject: String, issuer: String = TurnstileCrypto.URandom().secureToken, expires: TimeInterval) throws -> String {
        return try Passwordless.token(for: subject, issuer: issuer, expires: Date() + expires).createToken()
    }
    
    static func issuer(age: TimeInterval) -> Cookie {
        let issuer = TurnstileCrypto.URandom().secureToken
        return Cookie(name: "iss", value: issuer, expires: Date() + age, maxAge: Int(age), secure: true)
    }
    
    @discardableResult static func verify(request: Request) throws -> TokenPayload {
        guard let tokenString = request.headers.Bearer else {
            throw Abort.custom(status: .badRequest, message: "Authorization token is required.")
        }
        
        guard let token = try? JWT(token: tokenString),
            let _ = try? token.verifySignatureWith(signer),
            let subject = token.payload["sub"]?.string else {
                throw Abort.custom(status: .unauthorized, message: "Invalid Authorization token. The token cannot be verified.")
        }
        
        guard let cachedTokenString = try cache.get(subject)?.string,
            let cachedToken = try? JWT(token: cachedTokenString) else {
                throw Abort.custom(status: .unauthorized, message: "Token has expired, or has already been used.")
        }
        
        guard cachedTokenString == tokenString,
            let _subject = cachedToken.payload["sub"]?.string,
            let issuer = token.payload["iss"]?.string else {
                throw Abort.custom(status: .unauthorized, message: "The token was not of the correct type, or has already been used.")
        }
        
        guard request.cookies.contains(where: { $0.value == issuer }) else {
            throw Abort.custom(status: .unauthorized, message: "You must continue authentication on the same device")
        }
        
        return (cachedToken, _subject, issuer)
    }

}

extension HTTP.KeyAccessible where Key == HeaderKey, Value == String {
    var Bearer: String? {
        return Authorization?.components(separatedBy: " ").last
    }
    
    var Authorization: String? {
        get {
            return self["Authorization"]
        }
        set {
            self["Authorization"] = newValue
        }
    }
}
