import Foundation
import Darwin
import NetGuardCore

struct DurableState: Codable {
    var configuration: GuardConfiguration = .init()
    var lockdown = true
}

// No symlink traversal at the final directory or file, and no user-writable
// settings are accepted. Settings survive snapshot expiration and reboot.
final class ConfigurationStore {
    private let directory: URL
    init(directory: URL) { self.directory = directory }
    private func folder(create: Bool) throws -> Int32 {
        guard geteuid() == 0 else { throw PlatformError.unsafePolicy }
        if create && mkdir(directory.path, 0o755) != 0 && errno != EEXIST { throw PlatformError.unsafePolicy }
        let fd = open(directory.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw PlatformError.unsafePolicy }
        var st = stat()
        guard fstat(fd, &st) == 0, st.st_uid == 0, st.st_mode & 0o022 == 0 else { close(fd); throw PlatformError.unsafePolicy }
        return fd
    }
    func load() throws -> DurableState {
        let dir = try folder(create: true); defer { close(dir) }
        let fd = openat(dir, "settings.json", O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        if fd < 0 && errno == ENOENT { return DurableState() }
        guard fd >= 0 else { throw PlatformError.unsafePolicy }
        defer { close(fd) }
        var st = stat()
        guard fstat(fd, &st) == 0, st.st_uid == 0, st.st_nlink == 1,
              st.st_mode & S_IFMT == S_IFREG, st.st_mode & 0o077 == 0,
              st.st_size > 0, st.st_size <= 262144 else { throw PlatformError.unsafePolicy }
        var data = Data(count: Int(st.st_size)); var done = 0
        while done < data.count {
            let n = data.withUnsafeMutableBytes { Darwin.read(fd, $0.baseAddress!.advanced(by: done), data.count - done) }
            guard n > 0 else { throw PlatformError.unsafePolicy }; done += n
        }
        return try JSONDecoder().decode(DurableState.self, from: data)
    }
    func save(_ state: DurableState) throws {
        let data = try JSONEncoder().encode(state)
        guard data.count <= 262144 else { throw PlatformError.unsafePolicy }
        let dir = try folder(create: true); defer { close(dir) }
        let name = ".settings-" + UUID().uuidString
        let fd = openat(dir, name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard fd >= 0 else { throw PlatformError.unsafePolicy }
        defer { close(fd); unlinkat(dir, name, 0) }
        var done = 0
        while done < data.count {
            let n = data.withUnsafeBytes { Darwin.write(fd, $0.baseAddress!.advanced(by: done), data.count - done) }
            guard n > 0 else { throw PlatformError.unsafePolicy }; done += n
        }
        guard fchmod(fd, 0o600) == 0, fsync(fd) == 0,
              renameat(dir, name, dir, "settings.json") == 0, fsync(dir) == 0 else { throw PlatformError.unsafePolicy }
    }
}
