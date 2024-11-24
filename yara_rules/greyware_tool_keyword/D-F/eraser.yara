rule eraser
{
    meta:
        description = "Detection patterns for the tool 'eraser' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "eraser"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: It completely removes sensitive data from your hard drive by overwriting it several times with carefully selected patterns - abusedby attackers for anti forensic
        // Reference: https://sourceforge.net/projects/eraser
        $string1 = /\serase\s\/quiet\s\/method\=.{0,1000}\sdata\sdir\=/ nocase ascii wide
        // Description: It completely removes sensitive data from your hard drive by overwriting it several times with carefully selected patterns - abusedby attackers for anti forensic
        // Reference: https://sourceforge.net/projects/eraser
        $string2 = /\serase\s\/quiet\s\/methodName\=.{0,1000}\sdata\sdir\=/ nocase ascii wide
        // Description: It completely removes sensitive data from your hard drive by overwriting it several times with carefully selected patterns - abusedby attackers for anti forensic
        // Reference: https://sourceforge.net/projects/eraser
        $string3 = /\/Eraser\s5\.8\.8\.exe/ nocase ascii wide
        // Description: It completely removes sensitive data from your hard drive by overwriting it several times with carefully selected patterns - abusedby attackers for anti forensic
        // Reference: https://sourceforge.net/projects/eraser
        $string4 = /\/Eraser\s6\.0\.10\.2620\.exe/ nocase ascii wide
        // Description: It completely removes sensitive data from your hard drive by overwriting it several times with carefully selected patterns - abusedby attackers for anti forensic
        // Reference: https://sourceforge.net/projects/eraser
        $string5 = /\/Eraser\s6\.0\.8\.2273\.exe/ nocase ascii wide
        // Description: It completely removes sensitive data from your hard drive by overwriting it several times with carefully selected patterns - abusedby attackers for anti forensic
        // Reference: https://sourceforge.net/projects/eraser
        $string6 = /\/Eraser\s6\.0\.9\.2343\.exe/ nocase ascii wide
        // Description: It completely removes sensitive data from your hard drive by overwriting it several times with carefully selected patterns - abusedby attackers for anti forensic
        // Reference: https://sourceforge.net/projects/eraser
        $string7 = /\/Eraser\s6\.2\.0\.2994\.exe/ nocase ascii wide
        // Description: It completely removes sensitive data from your hard drive by overwriting it several times with carefully selected patterns - abusedby attackers for anti forensic
        // Reference: https://sourceforge.net/projects/eraser
        $string8 = /\/EraserSetup\.exe/ nocase ascii wide
        // Description: It completely removes sensitive data from your hard drive by overwriting it several times with carefully selected patterns - abusedby attackers for anti forensic
        // Reference: https://sourceforge.net/projects/eraser
        $string9 = /\\AppData\\Local\\Temp\\eraserInstallBootstrapper\\/ nocase ascii wide
        // Description: It completely removes sensitive data from your hard drive by overwriting it several times with carefully selected patterns - abusedby attackers for anti forensic
        // Reference: https://sourceforge.net/projects/eraser
        $string10 = /\\Eraser\s\(x64\)\.msi/ nocase ascii wide
        // Description: It completely removes sensitive data from your hard drive by overwriting it several times with carefully selected patterns - abusedby attackers for anti forensic
        // Reference: https://sourceforge.net/projects/eraser
        $string11 = /\\Eraser\s\(x86\)\.msi/ nocase ascii wide
        // Description: It completely removes sensitive data from your hard drive by overwriting it several times with carefully selected patterns - abusedby attackers for anti forensic
        // Reference: https://sourceforge.net/projects/eraser
        $string12 = /\\Eraser\s5\.8\.8\.exe/ nocase ascii wide
        // Description: It completely removes sensitive data from your hard drive by overwriting it several times with carefully selected patterns - abusedby attackers for anti forensic
        // Reference: https://sourceforge.net/projects/eraser
        $string13 = /\\Eraser\s6\.0\.10\.2620\.exe/ nocase ascii wide
        // Description: It completely removes sensitive data from your hard drive by overwriting it several times with carefully selected patterns - abusedby attackers for anti forensic
        // Reference: https://sourceforge.net/projects/eraser
        $string14 = /\\Eraser\s6\.0\.8\.2273\.exe/ nocase ascii wide
        // Description: It completely removes sensitive data from your hard drive by overwriting it several times with carefully selected patterns - abusedby attackers for anti forensic
        // Reference: https://sourceforge.net/projects/eraser
        $string15 = /\\Eraser\s6\.0\.9\.2343\.exe/ nocase ascii wide
        // Description: It completely removes sensitive data from your hard drive by overwriting it several times with carefully selected patterns - abusedby attackers for anti forensic
        // Reference: https://sourceforge.net/projects/eraser
        $string16 = /\\Eraser\s6\.2\.0\.2994\.exe/ nocase ascii wide
        // Description: It completely removes sensitive data from your hard drive by overwriting it several times with carefully selected patterns - abusedby attackers for anti forensic
        // Reference: https://sourceforge.net/projects/eraser
        $string17 = /\\EraserSetup\.exe/ nocase ascii wide
        // Description: It completely removes sensitive data from your hard drive by overwriting it several times with carefully selected patterns - abusedby attackers for anti forensic
        // Reference: https://sourceforge.net/projects/eraser
        $string18 = /\\Microsoft\\Windows\\CurrentVersion\\Run\\Eraser/ nocase ascii wide
        // Description: It completely removes sensitive data from your hard drive by overwriting it several times with carefully selected patterns - abusedby attackers for anti forensic
        // Reference: https://sourceforge.net/projects/eraser
        $string19 = /\\Microsoft\\Windows\\Start\sMenu\\Programs\\Eraser\\Eraser\.lnk/ nocase ascii wide
        // Description: It completely removes sensitive data from your hard drive by overwriting it several times with carefully selected patterns - abusedby attackers for anti forensic
        // Reference: https://sourceforge.net/projects/eraser
        $string20 = /\\Program\sFiles\\Eraser\\/ nocase ascii wide
        // Description: It completely removes sensitive data from your hard drive by overwriting it several times with carefully selected patterns - abusedby attackers for anti forensic
        // Reference: https://sourceforge.net/projects/eraser
        $string21 = /\\Public\\Desktop\\Eraser\.lnk/ nocase ascii wide
        // Description: It completely removes sensitive data from your hard drive by overwriting it several times with carefully selected patterns - abusedby attackers for anti forensic
        // Reference: https://sourceforge.net/projects/eraser
        $string22 = /\\Windows\\Start\sMenu\\Programs\\Eraser\\Eraser\sVerify\.lnk/ nocase ascii wide
        // Description: It completely removes sensitive data from your hard drive by overwriting it several times with carefully selected patterns - abusedby attackers for anti forensic
        // Reference: https://sourceforge.net/projects/eraser
        $string23 = /\\Windows\\Start\sMenu\\Programs\\Eraser\\Eraser\sWebsite\.url/ nocase ascii wide
        // Description: It completely removes sensitive data from your hard drive by overwriting it several times with carefully selected patterns - abusedby attackers for anti forensic
        // Reference: https://sourceforge.net/projects/eraser
        $string24 = ">Eraser - Secure Information Removal Tool<" nocase ascii wide
        // Description: It completely removes sensitive data from your hard drive by overwriting it several times with carefully selected patterns - abusedby attackers for anti forensic
        // Reference: https://sourceforge.net/projects/eraser
        $string25 = ">Eraser Setup Bootstrapper<" nocase ascii wide
        // Description: It completely removes sensitive data from your hard drive by overwriting it several times with carefully selected patterns - abusedby attackers for anti forensic
        // Reference: https://sourceforge.net/projects/eraser
        $string26 = "47e484261a88ba1a895699d8ff0239e1f5089b4a96128e8e610e2b41a9bd4605" nocase ascii wide
        // Description: It completely removes sensitive data from your hard drive by overwriting it several times with carefully selected patterns - abusedby attackers for anti forensic
        // Reference: https://sourceforge.net/projects/eraser
        $string27 = "491301f6b3bc5074f978eb8ad5629923be5e5a750f43d7df96fc9c48612a0016" nocase ascii wide
        // Description: It completely removes sensitive data from your hard drive by overwriting it several times with carefully selected patterns - abusedby attackers for anti forensic
        // Reference: https://sourceforge.net/projects/eraser
        $string28 = "4ce2ba1b4eabaf58b763ac456397b43ece17e9803e806bf405b28c386a484f6a" nocase ascii wide
        // Description: It completely removes sensitive data from your hard drive by overwriting it several times with carefully selected patterns - abusedby attackers for anti forensic
        // Reference: https://sourceforge.net/projects/eraser
        $string29 = "9d3a9deeeac5f53514e20f1a6dacd125ddec7e17e18d27c23a276ed5eb608878" nocase ascii wide
        // Description: It completely removes sensitive data from your hard drive by overwriting it several times with carefully selected patterns - abusedby attackers for anti forensic
        // Reference: https://sourceforge.net/projects/eraser
        $string30 = "a03578a6b28aff267f20a87755696a91a1d5b923e815b2989e4afcc8915cc357" nocase ascii wide
        // Description: It completely removes sensitive data from your hard drive by overwriting it several times with carefully selected patterns - abusedby attackers for anti forensic
        // Reference: https://sourceforge.net/projects/eraser
        $string31 = "a09787812790b59ec3d36120788ae9f80b7bdda1e2d7a17a46d8112324632737" nocase ascii wide
        // Description: It completely removes sensitive data from your hard drive by overwriting it several times with carefully selected patterns - abusedby attackers for anti forensic
        // Reference: https://sourceforge.net/projects/eraser
        $string32 = "bbc22b7149e74ee2ca344ebc55207e6bae4837b77857c7e9ef9e16682d7c8c49" nocase ascii wide
        // Description: It completely removes sensitive data from your hard drive by overwriting it several times with carefully selected patterns - abusedby attackers for anti forensic
        // Reference: https://sourceforge.net/projects/eraser
        $string33 = "ee4026fe96e047558bedd20cf870d1f8348beb91a2c88fbf4cedd6357e316f1d" nocase ascii wide
        // Description: It completely removes sensitive data from your hard drive by overwriting it several times with carefully selected patterns - abusedby attackers for anti forensic
        // Reference: https://sourceforge.net/projects/eraser
        $string34 = /Eraser\.exe\saddtask\s/ nocase ascii wide
        // Description: It completely removes sensitive data from your hard drive by overwriting it several times with carefully selected patterns - abusedby attackers for anti forensic
        // Reference: https://sourceforge.net/projects/eraser
        $string35 = /PortableApps\.com\/EraserPortable/ nocase ascii wide
        // Description: It completely removes sensitive data from your hard drive by overwriting it several times with carefully selected patterns - abusedby attackers for anti forensic
        // Reference: https://sourceforge.net/projects/eraser
        $string36 = /sourceforge\.net\/projects\/eraser\/files\/Eraser.{0,1000}\/download/ nocase ascii wide

    condition:
        any of them
}
