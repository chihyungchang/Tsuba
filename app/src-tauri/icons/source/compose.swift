// Put the rendered guard on the vermilion icon plate (macOS icon grid: 824 rounded square on a 1024 canvas).
// Run: swift compose.swift <guard.png> <out.png>
import AppKit

let args = CommandLine.arguments
let guardImage = NSImage(contentsOfFile: args[1])!
let size = 1024
let rep = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: size, pixelsHigh: size, bitsPerSample: 8, samplesPerPixel: 4,
                           hasAlpha: true, isPlanar: false, colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0)!
NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: rep)

let plate = NSBezierPath(roundedRect: NSRect(x: 100, y: 100, width: 824, height: 824), xRadius: 185, yRadius: 185)
let vermilion = NSGradient(starting: NSColor(srgbRed: 0xea / 255, green: 0x76 / 255, blue: 0x50 / 255, alpha: 1),
                           ending: NSColor(srgbRed: 0xb3 / 255, green: 0x30 / 255, blue: 0x1b / 255, alpha: 1))!
// AppKit's y axis points up: -45° runs from the top left to the bottom right
vermilion.draw(in: plate, angle: -45)
// The cast shadow may reach past the plate; keep everything inside it
plate.addClip()
guardImage.draw(in: NSRect(x: 0, y: 0, width: size, height: size))

NSGraphicsContext.current = nil
try! rep.representation(using: .png, properties: [:])!.write(to: URL(fileURLWithPath: args[2]))
