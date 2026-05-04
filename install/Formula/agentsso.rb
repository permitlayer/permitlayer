# Homebrew formula for agentsso, the permitlayer daemon binary.
class Agentsso < Formula
  desc "Binary: axum server, CLI, lifecycle management"
  homepage "https://github.com/permitlayer/permitlayer"
  version "0.3.0-rc.7"
  if OS.mac?
    if Hardware::CPU.arm?
      url "https://github.com/permitlayer/permitlayer/releases/download/v0.3.0-rc.7/permitlayer-daemon-aarch64-apple-darwin.tar.xz"
      sha256 "11b40b2ddcf0ae3fc87ed542930adab0ac97346fdba6144e929bedc82a2c1dab"
    end
    if Hardware::CPU.intel?
      url "https://github.com/permitlayer/permitlayer/releases/download/v0.3.0-rc.7/permitlayer-daemon-x86_64-apple-darwin.tar.xz"
      sha256 "2cb8032bf166f4fd22bf377277aaa0991cfcbdebd60ed658205fd163d011a17d"
    end
  end
  if OS.linux? && Hardware::CPU.intel?
    url "https://github.com/permitlayer/permitlayer/releases/download/v0.3.0-rc.7/permitlayer-daemon-x86_64-unknown-linux-gnu.tar.xz"
    sha256 "748100e69fc891209da55d6bfeaebf4f65bdd14842aadd0ccab7708ba15f8ab8"
  end
  license "MIT"

  BINARY_ALIASES = {
    "aarch64-apple-darwin":     {},
    "x86_64-apple-darwin":      {},
    "x86_64-pc-windows-gnu":    {},
    "x86_64-unknown-linux-gnu": {},
  }.freeze

  def target_triple
    cpu = Hardware::CPU.arm? ? "aarch64" : "x86_64"
    os = OS.mac? ? "apple-darwin" : "unknown-linux-gnu"

    "#{cpu}-#{os}"
  end

  def install_binary_aliases!
    BINARY_ALIASES[target_triple.to_sym].each do |source, dests|
      dests.each do |dest|
        bin.install_symlink bin/source.to_s => dest
      end
    end
  end

  def install
    bin.install "agentsso" if OS.mac? && Hardware::CPU.arm?
    bin.install "agentsso" if OS.mac? && Hardware::CPU.intel?
    bin.install "agentsso" if OS.linux? && Hardware::CPU.intel?

    install_binary_aliases!

    # Homebrew will automatically install these, so we don't need to do that
    doc_files = Dir["README.*", "readme.*", "LICENSE", "LICENSE.*", "CHANGELOG.*"]
    leftover_contents = Dir["*"] - doc_files

    # Install any leftover files in pkgshare; these are probably config or
    # sample files.
    pkgshare.install(*leftover_contents) unless leftover_contents.empty?
  end

  def caveats
    <<~EOS
      permitlayer is installed. To get started:

          agentsso setup gmail

      To run the daemon as a Homebrew-managed background service:

          brew services start agentsso

      If `agentsso` is already running (you started it manually with
      `agentsso start`), stop it first with `agentsso stop` — `brew
      services start` cannot take over a port already bound by another
      process. Always verify the result with `brew services list`.

      Or start it yourself:

          agentsso start

      Enable login-autostart instead (separate from brew services):

          agentsso autostart enable

      Docs: https://github.com/permitlayer/permitlayer
    EOS
  end

  service do
    run [opt_bin/"agentsso", "start"]
    # Restart only on real crashes (signal-killed: SIGSEGV, SIGABRT,
    # OOM-kill, etc.). Don't respawn on deliberate non-zero exits like
    # `agentsso start`'s exit-3 when it detects an already-running
    # daemon — that's a configuration conflict, not a crash, and
    # respawn-looping it just produces noisy launchd `error 78` rows
    # in `brew services list` without resolving the conflict.
    keep_alive crashed: true
    log_path var/"log/agentsso.log"
    error_log_path var/"log/agentsso.log"
    working_dir HOMEBREW_PREFIX
  end
end
