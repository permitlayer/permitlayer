# Homebrew formula for agentsso, the permitlayer daemon binary.
class Agentsso < Formula
  desc "Binary: axum server, CLI, lifecycle management"
  homepage "https://github.com/permitlayer/permitlayer"
  version "0.3.0-rc.5"
  if OS.mac?
    if Hardware::CPU.arm?
      url "https://github.com/permitlayer/permitlayer/releases/download/v0.3.0-rc.5/permitlayer-daemon-aarch64-apple-darwin.tar.xz"
      sha256 "f96850f18125a0a82273a679a746ca66aa50d38c1df30ea5ccc17e317b199819"
    end
    if Hardware::CPU.intel?
      url "https://github.com/permitlayer/permitlayer/releases/download/v0.3.0-rc.5/permitlayer-daemon-x86_64-apple-darwin.tar.xz"
      sha256 "463001f50970f805e0f1fd9178b8b8686e7947b03312688478a1666f3a8fdd1f"
    end
  end
  if OS.linux? && Hardware::CPU.intel?
    url "https://github.com/permitlayer/permitlayer/releases/download/v0.3.0-rc.5/permitlayer-daemon-x86_64-unknown-linux-gnu.tar.xz"
    sha256 "ecda41d42aa0ad1a549cacecd5be5f84ae04fdeccf7d298627e9b7dbc65ae90a"
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
