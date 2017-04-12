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

    static var tokenKey: String = "access_token"
    static var tempTokenExp: TimeInterval = 900.0 // fifteen minutes
    static var tokenExp: TimeInterval = 0.0
    static var subject = "email"
    static var medium: TokenMedium = .header
    static var sameDevice = true
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
    static func add(token: String, to response: HTTP.Response) {
        switch Provider.medium {
        case .body:
            response.json = response.json ?? JSON([:])
            response.json?[Provider.tokenKey] = JSON(Node(token))
        case .header:
            response.headers[HeaderKey(Provider.tokenKey)] = token
        case .cookie:
            response.cookies.insert(Cookie(name: Provider.tokenKey, value: token))
        }
    }

    static func extract(key: String, from token: JWT) -> String? {
        return token.payload[key]?.node.object?[key]?.string
    }

    static func tempToken(for subject: String, issuer: String = TurnstileCrypto.URandom().secureToken) throws -> String {
        let payload = try Node(node: [
            "iss": Node(IssuerClaim(issuer)),
            "sub": Node(SubjectClaim(subject)),
            "exp": Node(ExpirationTimeClaim(Date() + Provider.tempTokenExp))
        ])
        return try JWT(payload: payload, signer: Provider.signer).createToken()
    }

    static func issuer(age: TimeInterval, issuer: String = TurnstileCrypto.URandom().secureToken) -> Cookie {
        return Cookie(name: "iss", value: issuer, expires: Date() + age, maxAge: Int(age), secure: true)
    }

    @discardableResult static func verify(request: Request) throws -> TokenPayload {
        var accessToken: AccessToken!

        if let token = request.data[Provider.tokenKey]?.string {
            accessToken = AccessToken(string: token)
        } else if let bearer = request.auth.header?.bearer {
            accessToken = bearer
        } else {
            throw Abort.custom(status: .badRequest, message: "\(Provider.tokenKey) is required.")
        }

        var token: JWT!

        do {
            token = try JWT(token: accessToken.string)
            let verified = try token.verifySignatureWith(Provider.signer)
            guard verified else {
                throw Abort.custom(status: .unauthorized, message: Status.unauthorized.reasonPhrase)
            }
        } catch {
            throw Abort.custom(status: .unauthorized, message: Status.unauthorized.reasonPhrase)
        }

        guard let subject = Provider.extract(key: "sub", from: token),
            let issuer = Provider.extract(key: "iss", from: token) else {
            throw Abort.custom(status: .unauthorized, message: Status.unauthorized.reasonPhrase)
        }

        guard let cachedTokenString = try cache.get(subject)?.string,
            cachedTokenString == accessToken.string else {
            throw Abort.custom(status: .unauthorized, message: "Token has expired, or has already been used.")
        }

        if Provider.sameDevice {
            guard request.cookies.contains(where: { $0.value == issuer }) else {
                throw Abort.custom(status: .unauthorized, message: "You must continue using the same device.")
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
            throw Error.config("No `passwordless.json` config file or jwt object")
        }

        guard let signerString = passwordless["signer"]?.string else {
            throw Error.config("No `signer` found in `passwordless.json` config.")
        }

        guard let key = passwordless["key"]?.string else {
            throw Error.config("No `key` found in `passwordless.json` config.")
        }

        guard let expiration = passwordless["token-expiration"]?.double else {
            throw Error.config("No `token-expiration` found in `passwordless.json` config.")
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

extension AuthError: AbortError {
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
        case .invalidBearerAuthorization:
            return "Invalid Bearer Authorization"
        case .noAuthorizationHeader:
            return "No Authorization Header"
        default:
            return status.reasonPhrase
        }
    }
}

extension Authorization {
    init(request: Request) {
        self.init(header: request.headers["Authorization"] ?? "")
    }
}
