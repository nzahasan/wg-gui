# Source of Casks/wg-gui.rb in github.com/nzahasan/homebrew-tap. The
# release workflow fills in version and sha256 and pushes it there.
cask "wg-gui" do
  version "0.1.0"
  sha256 "0000000000000000000000000000000000000000000000000000000000000000"

  url "https://github.com/nzahasan/wg-gui/releases/download/v#{version}/wg-gui-#{version}.zip"
  name "wg-gui"
  desc "Lightweight userspace WireGuard client with a menu-bar UI"
  homepage "https://github.com/nzahasan/wg-gui"

  depends_on macos: :ventura

  app "wg-gui.app"
  binary "#{appdir}/wg-gui.app/Contents/MacOS/wg-cli"

  # Stops the helper (it restores DNS and routes first) and removes what it
  # leaves in system folders. --zap also removes your profiles and settings.
  uninstall launchctl: "com.nzahasan.wg-gui.helper",
            quit:      "com.nzahasan.wg-gui",
            delete:    [
              "/var/log/wg-gui-helper.log",
              "/var/run/com.nzahasan.wg-gui.helper.sock",
            ]

  zap trash: [
    "~/.config/wg-gui",
    "~/.wg-gui",
    "~/Library/Caches/com.nzahasan.wg-gui",
    "~/Library/HTTPStorages/com.nzahasan.wg-gui",
    "~/Library/Preferences/com.nzahasan.wg-gui.plist",
    "~/Library/Saved Application State/com.nzahasan.wg-gui.savedState",
  ]

  caveats <<~EOS
    On first launch, allow wg-gui's helper in
      System Settings → General → Login Items & Extensions → Allow in the Background
    It is the part that runs as root to bring tunnels up.
  EOS
end
