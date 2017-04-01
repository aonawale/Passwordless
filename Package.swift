import PackageDescription

let package = Package(
    name: "Passwordless",
    dependencies: [
        .Package(url: "https://github.com/vapor/vapor.git", majorVersion: 1, minor: 5),
        .Package(url:"https://github.com/vapor/jwt.git", majorVersion: 0, minor: 6)
    ]
)

