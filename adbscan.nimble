# Package
version       = "1.0.0"
author        = "Yardanico"
description   = "An utility for scanning IPs for unprotected ADB Android devices connected to the internet"
license       = "MIT"
srcDir        = "src"
bin           = @["adbscan"]

# Dependencies
requires "nim >= 0.20.2", "cligen"