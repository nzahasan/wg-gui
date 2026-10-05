# VPN icon bundle

## 1-AppIcon-macOS
- AppIcon.svg / AppIcon-1024.png – master app icon (824px tile, 185.4px continuous corner, on a 1024 canvas)
- AppIcon.icns – drop-in icon file for legacy builds
- AppIcon.iconset – source for `iconutil -c icns AppIcon.iconset`
- AppIcon.appiconset – drag into Assets.xcassets in Xcode

## 2-IconComposer-Layers
Full-bleed 1024px layers for Apple's Icon Composer (macOS 26 / 27).
Import in order: 1 background, 2 square, 3 circle. Icon Composer applies the
rounded mask and Liquid Glass effects and generates dark/tinted variants.

## 3-MenuBar
- vpn-tray-off-template – VPN off. Name ends in "Template" so macOS tints it automatically.
- vpn-tray-on-light / vpn-tray-on-dark – VPN on, green dot (#34C759).
- Xcode-Assets/VPNStatusOff.imageset – template image
- Xcode-Assets/VPNStatusOn.imageset – light/dark variants; macOS picks the right one automatically

```swift
statusItem.button?.image = NSImage(named: isConnected ? "VPNStatusOn" : "VPNStatusOff")
```

## 4-Logo
Dark tile, black mark and white mark for websites, docs and light/dark backgrounds.

## Colours
Coral #FF7277 → #F0565C · Charcoal #26272B · Active green #34C759
