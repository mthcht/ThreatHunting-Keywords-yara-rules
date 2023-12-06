rule pyshell
{
    meta:
        description = "Detection patterns for the tool 'pyshell' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "pyshell"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: PyShell is Multiplatform Python WebShell. This tool helps you to obtain a shell-like interface on a web server to be remotely accessed. Unlike other webshells the main goal of the tool is to use as little code as possible on the server side regardless of the language used or the operating system of the server.
        // Reference: https://github.com/JoelGMSec/PyShell
        $string1 = /\.\/PyShell\s/ nocase ascii wide
        // Description: PyShell is Multiplatform Python WebShell. This tool helps you to obtain a shell-like interface on a web server to be remotely accessed. Unlike other webshells the main goal of the tool is to use as little code as possible on the server side regardless of the language used or the operating system of the server.
        // Reference: https://github.com/JoelGMSec/PyShell
        $string2 = /\/JoelGMSec\/PyShell/ nocase ascii wide
        // Description: PyShell is Multiplatform Python WebShell. This tool helps you to obtain a shell-like interface on a web server to be remotely accessed. Unlike other webshells the main goal of the tool is to use as little code as possible on the server side regardless of the language used or the operating system of the server.
        // Reference: https://github.com/JoelGMSec/PyShell
        $string3 = /\/Shells\/shell\.aspx/ nocase ascii wide
        // Description: PyShell is Multiplatform Python WebShell. This tool helps you to obtain a shell-like interface on a web server to be remotely accessed. Unlike other webshells the main goal of the tool is to use as little code as possible on the server side regardless of the language used or the operating system of the server.
        // Reference: https://github.com/JoelGMSec/PyShell
        $string4 = /\/Shells\/shell\.jsp/ nocase ascii wide
        // Description: PyShell is Multiplatform Python WebShell. This tool helps you to obtain a shell-like interface on a web server to be remotely accessed. Unlike other webshells the main goal of the tool is to use as little code as possible on the server side regardless of the language used or the operating system of the server.
        // Reference: https://github.com/JoelGMSec/PyShell
        $string5 = /\/Shells\/shell\.php/ nocase ascii wide
        // Description: PyShell is Multiplatform Python WebShell. This tool helps you to obtain a shell-like interface on a web server to be remotely accessed. Unlike other webshells the main goal of the tool is to use as little code as possible on the server side regardless of the language used or the operating system of the server.
        // Reference: https://github.com/JoelGMSec/PyShell
        $string6 = /\/Shells\/shell\.py/ nocase ascii wide
        // Description: PyShell is Multiplatform Python WebShell. This tool helps you to obtain a shell-like interface on a web server to be remotely accessed. Unlike other webshells the main goal of the tool is to use as little code as possible on the server side regardless of the language used or the operating system of the server.
        // Reference: https://github.com/JoelGMSec/PyShell
        $string7 = /\/Shells\/shell\.sh/ nocase ascii wide
        // Description: PyShell is Multiplatform Python WebShell. This tool helps you to obtain a shell-like interface on a web server to be remotely accessed. Unlike other webshells the main goal of the tool is to use as little code as possible on the server side regardless of the language used or the operating system of the server.
        // Reference: https://github.com/JoelGMSec/PyShell
        $string8 = /\/Shells\/tomcat\.war/ nocase ascii wide
        // Description: PyShell is Multiplatform Python WebShell. This tool helps you to obtain a shell-like interface on a web server to be remotely accessed. Unlike other webshells the main goal of the tool is to use as little code as possible on the server side regardless of the language used or the operating system of the server.
        // Reference: https://github.com/JoelGMSec/PyShell
        $string9 = /\/Shells\/wordpress\.zip/ nocase ascii wide

    condition:
        any of them
}
