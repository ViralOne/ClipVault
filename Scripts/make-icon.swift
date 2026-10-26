#!/usr/bin/env swift
import AppKit
import CoreGraphics
import Foundation

// Renders the 1024×1024 ClipVault icon: a deep-blue squircle with a white
// clipboard whose sheet carries a vault dial. Converted to .icns by
// Scripts/make-icon.sh. Pure Core Graphics, so the icon is reproducible.

guard CommandLine.arguments.count > 1 else {
    FileHandle.standardError.write(Data("usage: make-icon.swift <out.png>\n".utf8))
    exit(2)
}

let side = 1024
let space = CGColorSpace(name: CGColorSpace.displayP3)!
guard let ctx = CGContext(
    data: nil, width: side, height: side, bitsPerComponent: 8, bytesPerRow: 0,
    space: space, bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue
) else { exit(1) }

func color(_ r: CGFloat, _ g: CGFloat, _ b: CGFloat, _ a: CGFloat = 1) -> CGColor {
    CGColor(colorSpace: space, components: [r, g, b, a])!
}

func linear(_ colors: [CGColor], _ locations: [CGFloat]) -> CGGradient {
    CGGradient(colorsSpace: space, colors: colors as CFArray, locations: locations)!
}

/// Apple-style continuous-corner rectangle approximated by a superellipse.
func squircle(_ rect: CGRect, exponent n: CGFloat = 4.4) -> CGPath {
    let path = CGMutablePath()
    let a = rect.width / 2, b = rect.height / 2
    let c = CGPoint(x: rect.midX, y: rect.midY)
    let steps = 720
    for i in 0...steps {
        let t = CGFloat(i) / CGFloat(steps) * 2 * .pi
        let cosT = cos(t), sinT = sin(t)
        let x = c.x + a * copysign(pow(abs(cosT), 2 / n), cosT)
        let y = c.y + b * copysign(pow(abs(sinT), 2 / n), sinT)
        i == 0 ? path.move(to: CGPoint(x: x, y: y)) : path.addLine(to: CGPoint(x: x, y: y))
    }
    path.closeSubpath()
    return path
}

func rounded(_ rect: CGRect, _ radius: CGFloat) -> CGPath {
    CGPath(roundedRect: rect, cornerWidth: radius, cornerHeight: radius, transform: nil)
}

// Core Graphics' origin is bottom-left; y grows upwards.
let tileRect = CGRect(x: 100, y: 100, width: 824, height: 824)
let tile = squircle(tileRect)

// MARK: Tile with drop shadow

ctx.saveGState()
ctx.setShadow(offset: CGSize(width: 0, height: -14), blur: 34, color: color(0, 0, 0, 0.32))
ctx.addPath(tile)
ctx.setFillColor(color(0.05, 0.2, 0.62))
ctx.fillPath()
ctx.restoreGState()

ctx.saveGState()
ctx.addPath(tile)
ctx.clip()
ctx.drawLinearGradient(
    linear([color(0.30, 0.62, 1.0), color(0.10, 0.40, 0.96), color(0.05, 0.22, 0.72)], [0, 0.5, 1]),
    start: CGPoint(x: 512, y: 924), end: CGPoint(x: 512, y: 100), options: []
)
// Soft top light.
ctx.drawRadialGradient(
    linear([color(1, 1, 1, 0.28), color(1, 1, 1, 0)], [0, 1]),
    startCenter: CGPoint(x: 512, y: 980), startRadius: 0,
    endCenter: CGPoint(x: 512, y: 980), endRadius: 620, options: []
)
ctx.restoreGState()

// Hairline inner edge.
ctx.saveGState()
ctx.addPath(tile)
ctx.setStrokeColor(color(1, 1, 1, 0.16))
ctx.setLineWidth(4)
ctx.strokePath()
ctx.restoreGState()

// MARK: Clipboard board

let board = CGRect(x: 262, y: 176, width: 500, height: 610)
ctx.saveGState()
ctx.setShadow(offset: CGSize(width: 0, height: -18), blur: 40, color: color(0.0, 0.05, 0.25, 0.45))
ctx.addPath(rounded(board, 74))
ctx.setFillColor(color(1, 1, 1))
ctx.fillPath()
ctx.restoreGState()

ctx.saveGState()
ctx.addPath(rounded(board, 74))
ctx.clip()
ctx.drawLinearGradient(
    linear([color(1, 1, 1), color(0.90, 0.93, 0.98)], [0, 1]),
    start: CGPoint(x: 512, y: board.maxY), end: CGPoint(x: 512, y: board.minY), options: []
)
ctx.restoreGState()

// MARK: Clip

let clip = CGRect(x: 392, y: 720, width: 240, height: 118)
ctx.saveGState()
ctx.setShadow(offset: CGSize(width: 0, height: -8), blur: 16, color: color(0, 0.05, 0.2, 0.35))
ctx.addPath(rounded(clip, 40))
ctx.setFillColor(color(0.6, 0.64, 0.72))
ctx.fillPath()
ctx.restoreGState()

ctx.saveGState()
ctx.addPath(rounded(clip, 40))
ctx.clip()
ctx.drawLinearGradient(
    linear([color(0.94, 0.95, 0.98), color(0.70, 0.74, 0.82), color(0.56, 0.60, 0.69)], [0, 0.55, 1]),
    start: CGPoint(x: 512, y: clip.maxY), end: CGPoint(x: 512, y: clip.minY), options: []
)
ctx.restoreGState()

// Hole in the clip.
let hole = CGRect(x: 482, y: 784, width: 60, height: 30)
ctx.addPath(rounded(hole, 15))
ctx.setFillColor(color(0.08, 0.30, 0.82))
ctx.fillPath()

// MARK: Vault dial

let center = CGPoint(x: 512, y: 430)
let dialRadius: CGFloat = 168

ctx.saveGState()
ctx.setShadow(offset: CGSize(width: 0, height: -10), blur: 22, color: color(0.0, 0.15, 0.55, 0.40))
ctx.addEllipse(in: CGRect(x: center.x - dialRadius, y: center.y - dialRadius, width: dialRadius * 2, height: dialRadius * 2))
ctx.setFillColor(color(0.1, 0.4, 0.95))
ctx.fillPath()
ctx.restoreGState()

ctx.saveGState()
ctx.addEllipse(in: CGRect(x: center.x - dialRadius, y: center.y - dialRadius, width: dialRadius * 2, height: dialRadius * 2))
ctx.clip()
ctx.drawLinearGradient(
    linear([color(0.36, 0.68, 1.0), color(0.10, 0.42, 0.97), color(0.04, 0.26, 0.80)], [0, 0.5, 1]),
    start: CGPoint(x: center.x, y: center.y + dialRadius), end: CGPoint(x: center.x, y: center.y - dialRadius),
    options: []
)
ctx.restoreGState()

// Graduations around the dial.
for i in 0..<40 {
    let angle = CGFloat(i) / 40 * 2 * .pi
    let major = i % 5 == 0
    let outer = dialRadius - 16
    let inner = outer - (major ? 30 : 16)
    ctx.move(to: CGPoint(x: center.x + cos(angle) * inner, y: center.y + sin(angle) * inner))
    ctx.addLine(to: CGPoint(x: center.x + cos(angle) * outer, y: center.y + sin(angle) * outer))
    ctx.setStrokeColor(color(1, 1, 1, major ? 0.95 : 0.55))
    ctx.setLineWidth(major ? 9 : 5)
    ctx.setLineCap(.round)
    ctx.strokePath()
}

// Inner hub.
let hubRadius: CGFloat = 84
ctx.saveGState()
ctx.setShadow(offset: CGSize(width: 0, height: -6), blur: 14, color: color(0, 0.1, 0.4, 0.45))
ctx.addEllipse(in: CGRect(x: center.x - hubRadius, y: center.y - hubRadius, width: hubRadius * 2, height: hubRadius * 2))
ctx.setFillColor(color(1, 1, 1))
ctx.fillPath()
ctx.restoreGState()

ctx.saveGState()
ctx.addEllipse(in: CGRect(x: center.x - hubRadius, y: center.y - hubRadius, width: hubRadius * 2, height: hubRadius * 2))
ctx.clip()
ctx.drawLinearGradient(
    linear([color(1, 1, 1), color(0.86, 0.90, 0.97)], [0, 1]),
    start: CGPoint(x: center.x, y: center.y + hubRadius), end: CGPoint(x: center.x, y: center.y - hubRadius),
    options: []
)
ctx.restoreGState()

// Keyhole.
let keyhole = CGMutablePath()
keyhole.addEllipse(in: CGRect(x: center.x - 24, y: center.y - 2, width: 48, height: 48))
keyhole.move(to: CGPoint(x: center.x - 13, y: center.y + 6))
keyhole.addLine(to: CGPoint(x: center.x - 22, y: center.y - 46))
keyhole.addQuadCurve(to: CGPoint(x: center.x + 22, y: center.y - 46), control: CGPoint(x: center.x, y: center.y - 54))
keyhole.addLine(to: CGPoint(x: center.x + 13, y: center.y + 6))
keyhole.closeSubpath()
ctx.addPath(keyhole)
ctx.setFillColor(color(0.06, 0.30, 0.86))
ctx.fillPath()

// Index mark above the dial.
let marker = CGMutablePath()
marker.move(to: CGPoint(x: center.x, y: center.y + dialRadius + 6))
marker.addLine(to: CGPoint(x: center.x - 18, y: center.y + dialRadius + 36))
marker.addLine(to: CGPoint(x: center.x + 18, y: center.y + dialRadius + 36))
marker.closeSubpath()
ctx.addPath(marker)
ctx.setFillColor(color(0.08, 0.34, 0.90))
ctx.fillPath()

guard let image = ctx.makeImage() else { exit(1) }
let rep = NSBitmapImageRep(cgImage: image)
guard let png = rep.representation(using: .png, properties: [:]) else { exit(1) }
try png.write(to: URL(fileURLWithPath: CommandLine.arguments[1]))
print("wrote \(CommandLine.arguments[1])")
