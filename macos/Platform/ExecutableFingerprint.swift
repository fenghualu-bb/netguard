import Foundation
import CryptoKit
import Darwin

// Discovery fingerprints describe bytes on disk. Runtime flow trust still requires
// a validated audit-token identity; a discovered hash does not attest a process.
enum ExecutableFingerprint {
    static func sha256(_ url: URL) -> String? {
        guard url.isFileURL else { return nil }
        let descriptor = open(url.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        guard descriptor >= 0 else { return nil }
        defer { close(descriptor) }
        var before = stat()
        guard fstat(descriptor, &before) == 0, before.st_mode & S_IFMT == S_IFREG,
              before.st_size > 0, before.st_size <= 1_073_741_824 else { return nil }
        var hash = SHA256()
        var buffer = [UInt8](repeating: 0, count: 65_536)
        var total = 0
        while total < before.st_size {
            let count = buffer.withUnsafeMutableBytes { Darwin.read(descriptor, $0.baseAddress, $0.count) }
            guard count > 0 else { return nil }
            hash.update(data: Data(buffer.prefix(count)))
            total += count
        }
        var after = stat()
        guard fstat(descriptor, &after) == 0, total == before.st_size,
              after.st_size == before.st_size, after.st_ino == before.st_ino,
              after.st_mtimespec.tv_sec == before.st_mtimespec.tv_sec,
              after.st_mtimespec.tv_nsec == before.st_mtimespec.tv_nsec,
              after.st_ctimespec.tv_sec == before.st_ctimespec.tv_sec,
              after.st_ctimespec.tv_nsec == before.st_ctimespec.tv_nsec else { return nil }
        return hash.finalize().map { String(format: "%02x", $0) }.joined()
    }
}
