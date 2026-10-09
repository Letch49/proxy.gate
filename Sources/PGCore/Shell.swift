import Foundation

/// Runs a command, captures stdout+stderr together, and always closes the pipe FDs afterwards.
/// One place for this so the Foundation Process+Pipe file-descriptor leak can't creep back in.
public enum Shell {
    @discardableResult
    public static func run(_ tool: String, _ args: [String], input: String? = nil) -> (status: Int32, output: String) {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: tool)
        process.arguments = args
        let out = Pipe()
        process.standardOutput = out
        process.standardError = out
        let inPipe = Pipe()
        process.standardInput = input == nil ? FileHandle.nullDevice : inPipe
        do { try process.run() } catch { return (-1, "\(error)") }
        if let input {
            inPipe.fileHandleForWriting.write(Data(input.utf8))
            try? inPipe.fileHandleForWriting.close()
        }
        let read = out.fileHandleForReading
        let data = read.readDataToEndOfFile()
        process.waitUntilExit()
        try? read.close()
        try? out.fileHandleForWriting.close()
        return (process.terminationStatus, String(decoding: data, as: UTF8.self))
    }
}
