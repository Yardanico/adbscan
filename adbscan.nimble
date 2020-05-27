# Package
version       = "1.1.0"
author        = "Danil Yarantsev (Yardanico)"
description   = "An utility for scanning IPs for unprotected ADB Android devices connected to the internet"
license       = "MIT"
srcDir        = "src"
bin           = @["adbscan"]

# Dependencies
requires "nim >= 1.0.0", "cligen"