import Vapor
import HTTP
import JWT
import Foundation
import Cache
import Cookies
import AuthProvider
import TurnstileCrypto

public final class Provider: Vapor.Provider {

    typealias TokenPayload = (token: JWT, sub: String, iss: String)

    enum TokenMedium: String {
        case header
        case cookie
        case body
    }

    static var tokenKey: String = "access_token"
    static var tempTokenExp: TimeInterval = 900.0 // fifteen minutes
    static var tokenExp: TimeInterval = 0.0
    static var subject = "email"
    static var medium: TokenMedium = .body
    static var sameDevice = true
    static var cache: CacheProtocol!
    static var signer: HMACSigner!

    public static var repositoryName: String {
        return ""
    }

    public convenience init(config: Config) throws {
        _ = try Provider.configure(config: config)
        self.init()
    }

    public func boot(_ config: Config) throws {

    }

    public func boot(_ droplet: Droplet) throws {
        Provider.cache = droplet.cache
    }

    public func beforeRun(_ droplet: Droplet) throws {

    }

    public func afterInit(_ drop: Droplet) {

    }

    public func beforeServe(_ drop: Droplet) {

    }

    public static func verifySignature(token: JWT) throws {
        do {
            try token.verifySignature(using: Passwordless.Provider.signer)
        } catch {
            throw AuthenticationError.invalidCredentials
        }
    }
}

extension Provider {
    static func add(token: String, subject: String, to response: HTTP.Response) throws {
        response.json = response.json ?? JSON()
        try response.json?.set(Provider.subject, subject)
        switch Provider.medium {
        case .body:
            try response.json?.set(Provider.tokenKey, token)
        case .header:
            response.headers[HeaderKey(Provider.tokenKey)] = token
        case .cookie:
            response.cookies.insert(Cookie(name: Provider.tokenKey, value: token))
        }
    }

    static func extract(key: String, from token: JWT) -> String? {
        return token.payload[key]?.string
    }

    static func tempToken(for subject: String, issuer: String = TurnstileCrypto.URandom().secureToken) throws -> String {
        var json = JSON()
        try json.set("iss", IssuerClaim(string: issuer).value)
        try json.set("sub", SubjectClaim(string: subject).value)
        try json.set("exp", ExpirationTimeClaim(createTimestamp: {
            Seconds((Date() + Provider.tempTokenExp).timeIntervalSince1970)
        }).value)

        return try JWT(payload: json, signer: Provider.signer).createToken()
    }

    static func issuer(age: TimeInterval, issuer: String = TurnstileCrypto.URandom().secureToken) -> Cookie {
        return Cookie(name: "iss", value: issuer, expires: Date() + age)
    }

    @discardableResult static func verifyToken(request: Request) throws -> (Token, JWT) {
        var accessToken: Token!

        if let token = request.data[Provider.tokenKey]?.string {
            accessToken = Token(string: token)
        } else if let bearer = request.auth.header?.bearer {
            accessToken = bearer
        } else {
            throw Abort(.badRequest, reason: "\(Provider.tokenKey) is required.")
        }

        var jwt: JWT!

        do {
            jwt = try JWT(token: accessToken.string)
            try jwt.verifySignature(using: Provider.signer)
        } catch {
            throw Abort(.unauthorized, reason: Status.unauthorized.reasonPhrase)
        }

        return (accessToken, jwt)
    }

    @discardableResult static func verify(request: Request) throws -> TokenPayload {
        let (accessToken, token) = try verifyToken(request: request)

        guard let subject = Provider.extract(key: "sub", from: token),
            let issuer = Provider.extract(key: "iss", from: token) else {
            throw Abort(.unauthorized, reason: Status.unauthorized.reasonPhrase)
        }

        guard let cachedTokenString = try cache.get(subject)?.string,
            cachedTokenString == accessToken.string else {
            throw Abort(.unauthorized, reason: "Token has expired, or has already been used.")
        }

        if Provider.sameDevice {
            guard request.cookies.contains(where: { $0.value == issuer }) else {
                throw Abort(.unauthorized, reason: "You must continue using the same device.")
            }
        }

        return (token, subject, issuer)
    }
}

extension Provider {
    public enum Error: Swift.Error {
        case config(String)
    }

    public static func configure(config: Config) throws {
        guard let passwordless = config["passwordless"]?.object else {
            throw Error.config("No `passwordless.json` config file found")
        }

        guard let signerString = passwordless["signer"]?.string else {
            throw Error.config("No `signer` specified in `passwordless.json` config.")
        }

        guard let key = passwordless["key"]?.string else {
            throw Error.config("No `key` specified in `passwordless.json` config.")
        }

        guard let expiration = passwordless["token-expiration"]?.double else {
            throw Error.config("No `token-expiration` specified in `passwordless.json` config.")
        }

        Provider.tokenExp = expiration
        Provider.tokenKey = passwordless["token-key"]?.string ?? "access_token"
        Provider.sameDevice = passwordless["same-device"]?.bool ?? true
        Provider.subject = passwordless["subject"]?.string ?? "email"

        if let mediumString = passwordless["token-medium"]?.string {
            guard let medium = TokenMedium(rawValue: mediumString) else {
                throw Error.config("Unsupported token medium `\(mediumString)` specified")
            }
            Provider.medium = medium
        }

        if let expiration = passwordless["temp-token-expiration"]?.double {
            Provider.tempTokenExp = expiration
        }

        switch signerString {
        case "hmac256":
            Provider.signer = HS256(key: key.makeBytes())
        case "hmac384":
            Provider.signer = HS384(key: key.makeBytes())
        case "hmac512":
            Provider.signer = HS512(key: key.makeBytes())
        default:
            throw Error.config("Unsupported signer '\(signerString)' specified.")
        }

    }
}

extension AuthorizationError {
    public var metadata: Node? {
        return nil
    }

    public var status: Status {
        return .unauthorized
    }

    public var code: Int {
        return status.statusCode
    }

    public var message: String {
        switch self {
        case .notAuthorized:
            return "Invalid Bearer Authorization"
        case .unknownPermission:
            return "No Authorization Header"
        default:
            return status.reasonPhrase
        }
    }
}
