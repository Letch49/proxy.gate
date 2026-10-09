import AppKit

/// The ProxyGate mark — an arrow entering a shield — drawn in code so the app icon and the
/// menu bar icon match. Self-contained (AppKit only): scripts/make-icon.swift compiles it to
/// produce AppIcon.icns.
enum GateIcon {
    /// Brand color of the shield in the menu bar (same hue family as the app icon).
    static let brand = NSColor(calibratedRed: 0.13, green: 0.55, blue: 0.72, alpha: 1)

    /// The mark as a standalone image (transparent background).
    static func glyph(size: CGFloat, shield: NSColor, arrow: NSColor) -> NSImage {
        NSImage(size: NSSize(width: size, height: size), flipped: false) { rect in
            drawGlyph(in: rect, shieldColor: shield, arrowColor: arrow)
            return true
        }
    }

    private static func drawGlyph(in rect: CGRect, shieldColor: NSColor, arrowColor: NSColor) {
        let s = rect.width
        func p(_ x: CGFloat, _ y: CGFloat) -> CGPoint { CGPoint(x: rect.minX + x * s, y: rect.minY + y * s) }

        // Shield, shifted right to leave room for the arrow.
        let shield = NSBezierPath()
        shield.move(to: p(0.60, 0.93))
        shield.curve(to: p(0.93, 0.79), controlPoint1: p(0.72, 0.86), controlPoint2: p(0.83, 0.82))
        shield.line(to: p(0.93, 0.52))
        shield.curve(to: p(0.60, 0.07), controlPoint1: p(0.93, 0.28), controlPoint2: p(0.78, 0.14))
        shield.curve(to: p(0.27, 0.52), controlPoint1: p(0.42, 0.14), controlPoint2: p(0.27, 0.28))
        shield.line(to: p(0.27, 0.79))
        shield.curve(to: p(0.60, 0.93), controlPoint1: p(0.37, 0.82), controlPoint2: p(0.48, 0.86))
        shield.close()
        shield.lineWidth = 0.075 * s
        shield.lineJoinStyle = .round
        shieldColor.setStroke()
        shield.stroke()

        // Arrow pointing into the shield.
        let shaft = NSBezierPath()
        shaft.move(to: p(0.06, 0.50))
        shaft.line(to: p(0.58, 0.50))
        shaft.lineCapStyle = .round

        // Cut a gap where the arrow crosses the shield outline, so the two read as separate shapes.
        if let context = NSGraphicsContext.current {
            context.saveGraphicsState()
            context.compositingOperation = .clear
            shaft.lineWidth = 0.21 * s
            shaft.stroke()
            context.restoreGraphicsState()
        }

        shaft.lineWidth = 0.085 * s
        arrowColor.setStroke()
        shaft.stroke()

        let head = NSBezierPath()
        head.move(to: p(0.74, 0.50))
        head.line(to: p(0.53, 0.66))
        head.line(to: p(0.53, 0.34))
        head.close()
        head.lineJoinStyle = .round
        head.lineWidth = 0.03 * s
        arrowColor.setFill()
        arrowColor.setStroke()
        head.fill()
        head.stroke()
    }

    /// Menu bar icon: brand-colored shield, the arrow shows the state (green on, red off).
    static func statusImage(running: Bool, size: CGFloat = 18) -> NSImage {
        let image = glyph(size: size, shield: brand, arrow: running ? .systemGreen : .systemRed)
        image.isTemplate = false
        image.accessibilityDescription = running ? "ProxyGate on" : "ProxyGate off"
        return image
    }

    /// Full app icon: gradient rounded square with a white mark.
    static func appIcon(size: CGFloat) -> NSImage {
        NSImage(size: NSSize(width: size, height: size), flipped: false) { rect in
            let inset = rect.insetBy(dx: size * 0.09, dy: size * 0.09)
            let shape = NSBezierPath(roundedRect: inset, xRadius: inset.width * 0.225, yRadius: inset.width * 0.225)
            NSGradient(colors: [
                NSColor(calibratedRed: 0.16, green: 0.72, blue: 0.62, alpha: 1),
                NSColor(calibratedRed: 0.10, green: 0.33, blue: 0.70, alpha: 1),
            ])?.draw(in: shape, angle: -70)
            let markRect = inset.insetBy(dx: inset.width * 0.17, dy: inset.width * 0.17)
            glyph(size: markRect.width, shield: .white, arrow: .white).draw(in: markRect)
            return true
        }
    }
}
