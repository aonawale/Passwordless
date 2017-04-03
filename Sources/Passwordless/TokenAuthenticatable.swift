import Auth
import Fluent

// from https://github.com/vapor/auth
public protocol TokenAuthenticatable {
    /// The token entity that contains a foreign key
    /// pointer to the user table (or on the user table itself)
    associatedtype TokenType

    /// Returns the user matching the supplied token.
    @discardableResult static func authenticate(_ token: AccessToken) throws -> Self

    /// The column under which the tokens are stored
    static var tokenKey: String { get }
}

extension TokenAuthenticatable {
    public static var tokenKey: String {
        return "token"
    }
}

// from https://github.com/vapor/auth
extension TokenAuthenticatable where Self: Entity, Self.TokenType: Entity {
    @discardableResult public static func authenticate(_ token: AccessToken) throws -> Self {
        guard let entity = try Self.query()
            .union(Self.TokenType.self)
            .filter(Self.TokenType.self, tokenKey, token.string)
            .first() else {
                throw AuthError.invalidCredentials
        }

        return entity
    }
}
