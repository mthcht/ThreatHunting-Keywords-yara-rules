rule chisel
{
    meta:
        description = "Detection patterns for the tool 'chisel' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "chisel"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string1 = /\sinstall\schisel/ nocase ascii wide
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string2 = /\/chisel\.exe/ nocase ascii wide
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string3 = /\/chisel\.git/ nocase ascii wide
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string4 = /\/chisel\/client\// nocase ascii wide
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string5 = /\/chisel\/server\// nocase ascii wide
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string6 = /\/chisel\@latest/ nocase ascii wide
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string7 = /\/chisel\-darwin_amd64/ nocase ascii wide
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string8 = /\/chisel\-freebsd/ nocase ascii wide
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string9 = /\/chisel\-linux_/ nocase ascii wide
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string10 = /\/chisel\-master/ nocase ascii wide
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string11 = /\/chisel\-windows_amd6/ nocase ascii wide
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string12 = /\\chisel\.exe/ nocase ascii wide
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string13 = /\\chisel\\client\\/ nocase ascii wide
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string14 = /\\chisel\\server\\/ nocase ascii wide
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string15 = /\\chisel\-master/ nocase ascii wide
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string16 = /chisel\s\-/ nocase ascii wide
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string17 = /chisel\sclient\s\-/ nocase ascii wide
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string18 = /chisel\sclient\shttp/ nocase ascii wide
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string19 = /chisel\sserver\s\-/ nocase ascii wide
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string20 = /chisel\.exe\sclient/ nocase ascii wide
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string21 = /chisel\.exe\sserver/ nocase ascii wide
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string22 = /chisel\.jpillora\.com/ nocase ascii wide
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string23 = /chisel_1.{0,1000}_darwin_.{0,1000}\.gz/ nocase ascii wide
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string24 = /chisel_1.{0,1000}_linux_.{0,1000}\.gz/ nocase ascii wide
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string25 = /chisel_linux_amd64/ nocase ascii wide
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string26 = /chisel_windows_amd64\.exe/ nocase ascii wide
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string27 = /chisel\-master\.zip/ nocase ascii wide
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string28 = /jpillora\/chisel/ nocase ascii wide
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string29 = /\-local\=0\.0\.0\.0:4001/ nocase ascii wide
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string30 = /\-\-name\schisel\s\-p\s/ nocase ascii wide
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string31 = /\-remote\=127\.0\.0\.1:3000/ nocase ascii wide
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string32 = /\-server\=http:\/\/127\.0\.0\.1:4002/ nocase ascii wide

    condition:
        any of them
}
