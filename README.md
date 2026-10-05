# wg-gui

A small userspace WireGuard client for macOS, with a desktop window and a
menu-bar icon.

## Install

```sh
brew install --cask nzahasan/tap/wg-gui
```

On first launch, macOS asks you to allow wg-gui's helper under
**System Settings → General → Login Items → Allow in the Background**
(the app shows a button that opens it). The helper is the small part that
runs as root to create the tunnel and set routes and DNS; the app itself
runs as you. The cask also puts `wg-cli` on your PATH (`sudo wg-cli
profile.conf`).

Uninstall with `brew uninstall --cask wg-gui` (add `--zap` to also remove
your profiles in `~/.wg-gui`). If you installed by hand instead, choose
**Uninstall Helper…** in the menu-bar menu before deleting the app; it
stops the helper and removes it from Login Items.

## How it is put together

- `wg-gui`: the app, running as the user. Profiles live in `~/.wg-gui`.
- `wg-helper`: a root launchd daemon inside `wg-gui.app`, registered with
  SMAppService. It listens on `/var/run/com.nzahasan.wg-gui.helper.sock`
  and only serves the wg-gui app signed by our team. A tunnel goes down
  when the app that started it disconnects or quits.
- `wg-cli`: the same tunnel from a terminal, run with sudo.

## Development

```sh
cargo test --features gui
cargo helper && sudo target/release/wg-helper --dev --socket /tmp/wg.sock
# in another terminal
cargo gui && WG_HELPER_SOCKET=/tmp/wg.sock target/release/wg-gui
```

`--dev` skips the helper's signature check; only use it on your own machine.

## Releasing

`packaging/macos/build-app.sh` builds `dist/wg-gui.app` and the zip for the
cask (`TARGETS=native` builds for this Mac only, ad-hoc signed, when no
signing identity is set). Pushing a `v*` tag runs
`.github/workflows/release.yml`, which builds a universal app, signs and
notarizes it, attaches it to the GitHub release and updates
`Casks/wg-gui.rb` in `nzahasan/homebrew-tap` from
`packaging/homebrew/wg-gui.rb`.

## License

MIT — see [LICENSE](LICENSE).
