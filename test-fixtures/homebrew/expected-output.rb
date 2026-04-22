# Homebrew formula for agentsso, the permitlayer daemon binary.
class Agentsso < Formula
  desc "agentsso binary: axum server, CLI, lifecycle management"
  homepage "https://github.com/permitlayer/permitlayer"
  version "0.2.0"
  if OS.mac?
    if Hardware::CPU.arm?
      url "https://github.com/permitlayer/permitlayer/releases/download/v0.2.0/permitlayer-daemon-aarch64-apple-darwin.tar.xz"
    end
    if Hardware::CPU.intel?
      url "https://github.com/permitlayer/permitlayer/releases/download/v0.2.0/permitlayer-daemon-x86_64-apple-darwin.tar.xz"
    end
  end
  license "MIT"

  BINARY_ALIASES = {
    "aarch64-apple-darwin": {},
    "x86_64-apple-darwin": {}
  }

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
    if OS.mac? && Hardware::CPU.arm?
      bin.install "agentsso"
    end
    if OS.mac? && Hardware::CPU.intel?
      bin.install "agentsso"
    end

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

      Or start it yourself:

          agentsso start

      Enable login-autostart instead (separate from brew services):

          agentsso autostart enable

      Docs: https://github.com/permitlayer/permitlayer
    EOS
  end

  service do
    run [opt_bin/"agentsso", "start"]
    keep_alive true
    log_path var/"log/agentsso.log"
    error_log_path var/"log/agentsso.log"
    working_dir HOMEBREW_PREFIX
  end
end
