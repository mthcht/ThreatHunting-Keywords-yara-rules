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
        $string1 = /.{0,1000}\.\/PyShell\s.{0,1000}/ nocase ascii wide
        // Description: PyShell is Multiplatform Python WebShell. This tool helps you to obtain a shell-like interface on a web server to be remotely accessed. Unlike other webshells the main goal of the tool is to use as little code as possible on the server side regardless of the language used or the operating system of the server.
        // Reference: https://github.com/JoelGMSec/PyShell
        $string2 = /.{0,1000}\/JoelGMSec\/PyShell.{0,1000}/ nocase ascii wide
        // Description: PyShell is Multiplatform Python WebShell. This tool helps you to obtain a shell-like interface on a web server to be remotely accessed. Unlike other webshells the main goal of the tool is to use as little code as possible on the server side regardless of the language used or the operating system of the server.
        // Reference: https://github.com/JoelGMSec/PyShell
        $string3 = /.{0,1000}\/Shells\/shell\.aspx.{0,1000}/ nocase ascii wide
        // Description: PyShell is Multiplatform Python WebShell. This tool helps you to obtain a shell-like interface on a web server to be remotely accessed. Unlike other webshells the main goal of the tool is to use as little code as possible on the server side regardless of the language used or the operating system of the server.
        // Reference: https://github.com/JoelGMSec/PyShell
        $string4 = /.{0,1000}\/Shells\/shell\.jsp.{0,1000}/ nocase ascii wide
        // Description: PyShell is Multiplatform Python WebShell. This tool helps you to obtain a shell-like interface on a web server to be remotely accessed. Unlike other webshells the main goal of the tool is to use as little code as possible on the server side regardless of the language used or the operating system of the server.
        // Reference: https://github.com/JoelGMSec/PyShell
        $string5 = /.{0,1000}\/Shells\/shell\.php.{0,1000}/ nocase ascii wide
        // Description: PyShell is Multiplatform Python WebShell. This tool helps you to obtain a shell-like interface on a web server to be remotely accessed. Unlike other webshells the main goal of the tool is to use as little code as possible on the server side regardless of the language used or the operating system of the server.
        // Reference: https://github.com/JoelGMSec/PyShell
        $string6 = /.{0,1000}\/Shells\/shell\.py.{0,1000}/ nocase ascii wide
        // Description: PyShell is Multiplatform Python WebShell. This tool helps you to obtain a shell-like interface on a web server to be remotely accessed. Unlike other webshells the main goal of the tool is to use as little code as possible on the server side regardless of the language used or the operating system of the server.
        // Reference: https://github.com/JoelGMSec/PyShell
        $string7 = /.{0,1000}\/Shells\/shell\.sh.{0,1000}/ nocase ascii wide
        // Description: PyShell is Multiplatform Python WebShell. This tool helps you to obtain a shell-like interface on a web server to be remotely accessed. Unlike other webshells the main goal of the tool is to use as little code as possible on the server side regardless of the language used or the operating system of the server.
        // Reference: https://github.com/JoelGMSec/PyShell
        $string8 = /.{0,1000}\/Shells\/tomcat\.war.{0,1000}/ nocase ascii wide
        // Description: PyShell is Multiplatform Python WebShell. This tool helps you to obtain a shell-like interface on a web server to be remotely accessed. Unlike other webshells the main goal of the tool is to use as little code as possible on the server side regardless of the language used or the operating system of the server.
        // Reference: https://github.com/JoelGMSec/PyShell
        $string9 = /.{0,1000}\/Shells\/wordpress\.zip.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
