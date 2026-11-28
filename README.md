# NUP Loader

A standalone loader for the Nintendo Switch 2 (kaiHEN), built with devkitPro.

Currently only bootable on Fire Emblem Fortunes Weave (due to this actually needing traces from games lol.)

Can also boot Pokemon Z-A Switch2 Edition.

## Install

Use **our** kaiHEN and hbmenu builds. nup-loader talks to custom HEN commands
and the plugin settings service that upstream builds do not provide.

Download the newest non-prerelease (**Latest**) release from each repo:

- [kaiHEN](https://github.com/Doofenshmirtz-Homebrew-Incorporated/okaihen/releases/latest) — `okaihen.zip`
- [ounce-hbmenu](https://github.com/Doofenshmirtz-Homebrew-Incorporated/ounce-hbmenu/releases/latest) — `ounce-hbmenu.zip`
- [nup-loader](https://github.com/Doofenshmirtz-Homebrew-Incorporated/nup-loader/releases/latest) — `nup-loader.zip`

Each release has a `SHA256SUMS.txt`; run `sha256sum -c SHA256SUMS.txt` beside the
downloads before copying anything to the SD card.

1. Install our kaiHEN. From `okaihen.zip`, put `hen/main` at
   `/kaihen/bin/hen/main`. `ro/main` and `bootstrap.bin` are read by the
   acquisition tool that starts HEN, not from the SD card, so hand those two
   files to the tool. If you already have a kaiHEN SD card, replace its
   `hen/main` with ours and use our `ro/main`/`bootstrap.bin` with the tool.
2. Extract `ounce-hbmenu.zip` at the SD card root, giving `/hbmenu.nro`.
3. Extract `nup-loader.zip` at the SD card root. It already contains the final
   paths:

   ```
   /kaihen/programs/nup-loader.nro
   /kaihen/plugins/nupvfs.nso
   /switch/nup-loader/nup-loader.nro
   ```

   Reboot after this: `nupvfs.nso` is a boot-time plugin, so it is only started
   on the next boot. Its toggles are under **Settings → Plugins → nupvfs** in
   our hbmenu.
4. Launch A game via HBMenu. Make sure you got a SW1 game inserted or Downloaded at least for it to start a SW1 game.
5. If it crashes, open NUP-Loader and do a tracing run with Y.
6. Upload that as a Issue on Nup-Loaders Github.

Boot a native game while holding R, then launch nup-loader from hbmenu.

## Build

Requires [devkitPro](https://devkitpro.org/) with the Switch 2 toolchain installed and `DEVKITPRO` set.

```sh
make
```

Output: `nup-loader.nro` (and `.elf`).

## License

MIT — see [LICENSE](LICENSE).
