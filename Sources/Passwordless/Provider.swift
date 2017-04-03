import Vapor
import HTTP
import VaporJWT
import Foundation
import TurnstileCrypto
import Cache
import Cookies
import Auth

public final class Provider: Vapor.Provider {

    typealias TokenPayload = (token: JWT, sub: String, iss: String)

    enum TokenMedium: String {
        case header
        case cookie
        case body
    }

    static var subject: String = "email"
    static var medium: TokenMedium = .header
    static var sameDevice: Bool = true
    static var cache: CacheProtocol!
    static var signer: HMACSigner!

    public convenience init(config: Config) throws {
        _ = try Provider.configure(config: config)
        self.init()
    }

    public func boot(_ drop: Droplet) {
        Provider.cache = drop.cache
    }

    public func beforeRun(_: Droplet) {

    }

    public func afterInit(_ drop: Droplet) {

    }

    public func beforeServe(_ drop: Droplet) {

    }
}

extension Provider {
    static func token(for subject: String, issuer: String = TurnstileCrypto.URandom().secureToken, expires: Date) throws -> JWT {
        let payload = try Node(node: [
            "iss": issuer,
            "sub": subject,
            "exp": Node(ExpirationTimeClaim(expires))
        ])
        return try JWT(payload: payload, signer: Provider.signer)
    }

    static func tokenString(for subject: String, issuer: String = TurnstileCrypto.URandom().secureToken, expires: Date) throws -> String {
        return try Provider.token(for: subject, issuer: issuer, expires: expires).createToken()
    }

    static func tokenString(for subject: String, issuer: String = TurnstileCrypto.URandom().secureToken, expires: TimeInterval) throws -> String {
        return try Provider.token(for: subject, issuer: issuer, expires: Date() + expires).createToken()
    }

    static func issuer(age: TimeInterval) -> Cookie {
        let issuer = TurnstileCrypto.URandom().secureToken
        return Cookie(name: "iss", value: issuer, expires: Date() + age, maxAge: Int(age), secure: true)
    }

    @discardableResult static func verify(request: Request) throws -> TokenPayload {
        guard let accessToken = request.auth.header?.bearer else {
            throw Abort.custom(status: .badRequest, message: "Authorization token is required.")
        }

        guard let token = try? JWT(token: accessToken.string),
            let _ = try? token.verifySignatureWith(signer),
            let subject = token.payload["sub"]?.string else {
                throw Abort.custom(status: .unauthorized, message: "Invalid Authorization token. The token cannot be verified.")
        }

        guard let cachedTokenString = try cache.get(subject)?.string,
            let cachedToken = try? JWT(token: cachedTokenString) else {
                throw Abort.custom(status: .unauthorized, message: "Token has expired, or has already been used.")
        }

        guard cachedTokenString == accessToken.string,
            let _subject = cachedToken.payload["sub"]?.string,
            let issuer = token.payload["iss"]?.string else {
                throw Abort.custom(status: .unauthorized, message: "The token was not of the correct type, or has already been used.")
        }

        if Provider.sameDevice {
            guard request.cookies.contains(where: { $0.value == issuer }) else {
                throw Abort.custom(status: .unauthorized, message: "You must continue authentication on the same device")
            }
        }

        return (cachedToken, _subject, issuer)
    }
}

extension Provider {
    public enum Error: Swift.Error {
        case config(String)
    }

    public static func configure(config: Config) throws {
        guard let passwordless = config["passwordless"]?.object else {
            throw Error.config("No `passwordless.json` config file or jwt object")
        }

        guard let signerString = passwordless["signer"]?.string else {
            throw Error.config("No `signer` found in `passwordless.json` config.")
        }

        guard let key = passwordless["key"]?.string else {
            throw Error.config("No `key` found in `passwordless.json` config.")
        }

        Provider.sameDevice = passwordless["same-device"]?.bool ?? false
        Provider.subject = passwordless["same-device"]?.string ?? "email"

        let mediumString = passwordless["token-medium"]?.string ?? "header"

        guard let medium = TokenMedium(rawValue: mediumString) else {
            throw Error.config("Unsupported token medium `\(mediumString)` specified")
        }

        Provider.medium = medium

        switch signerString {
        case "hmac256":
            Provider.signer = HS256(key: key)
        case "hmac384":
            Provider.signer = HS384(key: key)
        case "hmac512":
            Provider.signer = HS512(key: key)
        default:
            throw Error.config("Unsupported signer '\(signerString)' specified.")
        }

    }
}

extension Authorization {
    init(request: Request) {
        self.init(header: request.headers["Authorization"] ?? "")
    }
}
