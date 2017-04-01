import Vapor
import Cache
import VaporJWT

public final class PasswordlessProvider: Vapor.Provider {
    public convenience init(config: Config) throws {
        _ = try Passwordless.configure(config: config)
        self.init()
    }

    public func boot(_ drop: Droplet) {
        Passwordless.cache = drop.cache
    }

    public func beforeRun(_: Droplet) {

    }

    public func afterInit(_ drop: Droplet) {

    }

    public func beforeServe(_ drop: Droplet) {

    }
}

extension Passwordless {
    public enum Error: Swift.Error {
        case config(String)
    }

    public static func configure(config: Config) throws {
        guard let jwt = config["crypto", "jwt"]?.object else {
            throw Error.config("No `crypto.json` config file or jwt object")
        }

        guard let signerString = jwt["signer"]?.string else {
            throw Error.config("No `jwt.signer` found in `crypto.json` config.")
        }

        guard let key = jwt["key"]?.string else {
            throw Error.config("No `jwt.key` found in `crypto.json` config.")
        }

        var signer: HMACSigner

        switch signerString {
        case "hmac256":
            signer = HS256(key: key)
        case "hmac384":
            signer = HS384(key: key)
        case "hmac512":
            signer = HS512(key: key)
        default:
            throw Error.config("Unknown signer '\(signerString)'.")
        }

        Passwordless.signer = signer
    }
}
