#!/usr/bin/env bash
set -euo pipefail

source_app=${1:?expected the built Release Zann.app}
destination=/Applications/Zann.app
stage=$(mktemp -d /Applications/.zann-install.XXXXXXXX)
trap 'rm -rf "$stage"' EXIT
ditto "$source_app" "$stage/Zann.app"
codesign --verify --strict "$stage/Zann.app"

# Use bundle identity to find running copies, including Xcode build products.
# Publish the complete bundle in one rename on the destination volume.
xcrun swift - "$stage/Zann.app" "$destination" <<'SWIFT'
import AppKit
import Darwin

func fail(_ message: String) -> Never {
    FileHandle.standardError.write(Data((message + "\n").utf8))
    exit(1)
}

let staged = URL(fileURLWithPath: CommandLine.arguments[1])
let destination = URL(fileURLWithPath: CommandLine.arguments[2])
guard let id = Bundle(url: staged)?.bundleIdentifier else {
    fail("Missing bundle identifier in \(staged.path)")
}
let updating = FileManager.default.fileExists(atPath: destination.path)
if updating {
    let attributes = try FileManager.default.attributesOfItem(atPath: destination.path)
    guard attributes[.type] as? FileAttributeType == .typeDirectory,
          Bundle(url: destination)?.bundleIdentifier == id else {
        fail("Another application or a symbolic link occupies \(destination.path)")
    }
}
let running = NSRunningApplication.runningApplications(withBundleIdentifier: id)
for app in running where !app.isTerminated {
    guard app.terminate() else { fail("Could not quit Zann (PID \(app.processIdentifier))") }
}
let deadline = Date().addingTimeInterval(15)
while running.contains(where: { !$0.isTerminated }) {
    guard Date() < deadline else { fail("Zann is still running. Quit it and retry the installation.") }
    RunLoop.current.run(until: Date().addingTimeInterval(0.1))
}
guard renamex_np(staged.path, destination.path, updating ? UInt32(RENAME_SWAP) : UInt32(RENAME_EXCL)) == 0 else {
    perror("Installing Zann.app")
    exit(1)
}
SWIFT

open "$destination"
