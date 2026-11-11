import Foundation
import Security

enum AuthorizationVerifier {
    static func verify(_ data: Data) -> Bool {
        guard data.count == MemoryLayout<AuthorizationExternalForm>.size else { return false }
        var form = AuthorizationExternalForm()
        _ = withUnsafeMutableBytes(of: &form) { data.copyBytes(to: $0) }
        var authorization: AuthorizationRef?
        guard AuthorizationCreateFromExternalForm(&form, &authorization) == errAuthorizationSuccess,
              let authorization else { return false }
        defer { AuthorizationFree(authorization, []) }
        return "system.privilege.admin".withCString { name in
            var item = AuthorizationItem(name: name, valueLength: 0, value: nil, flags: 0)
            return withUnsafeMutablePointer(to: &item) { ptr in
                var rights = AuthorizationRights(count: 1, items: ptr)
                // No interaction and no extension of rights inside the root service.
                return AuthorizationCopyRights(authorization, &rights, nil, [], nil) == errAuthorizationSuccess
            }
        }
    }
}
