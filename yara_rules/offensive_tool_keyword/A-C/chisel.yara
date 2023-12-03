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
        $string1 = /.{0,1000}\sinstall\schisel.{0,1000}/ nocase ascii wide
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string2 = /.{0,1000}\/chisel\.exe.{0,1000}/ nocase ascii wide
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string3 = /.{0,1000}\/chisel\.git.{0,1000}/ nocase ascii wide
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string4 = /.{0,1000}\/chisel\/client\/.{0,1000}/ nocase ascii wide
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string5 = /.{0,1000}\/chisel\/server\/.{0,1000}/ nocase ascii wide
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string6 = /.{0,1000}\/chisel\@latest.{0,1000}/ nocase ascii wide
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string7 = /.{0,1000}\/chisel\-darwin_amd64.{0,1000}/ nocase ascii wide
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string8 = /.{0,1000}\/chisel\-freebsd.{0,1000}/ nocase ascii wide
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string9 = /.{0,1000}\/chisel\-linux_.{0,1000}/ nocase ascii wide
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string10 = /.{0,1000}\/chisel\-master.{0,1000}/ nocase ascii wide
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string11 = /.{0,1000}\/chisel\-windows_amd6.{0,1000}/ nocase ascii wide
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string12 = /.{0,1000}\\chisel\.exe.{0,1000}/ nocase ascii wide
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string13 = /.{0,1000}\\chisel\\client\\.{0,1000}/ nocase ascii wide
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string14 = /.{0,1000}\\chisel\\server\\.{0,1000}/ nocase ascii wide
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string15 = /.{0,1000}\\chisel\-master.{0,1000}/ nocase ascii wide
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string16 = /.{0,1000}chisel\s\-.{0,1000}/ nocase ascii wide
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string17 = /.{0,1000}chisel\sclient\s\-.{0,1000}/ nocase ascii wide
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string18 = /.{0,1000}chisel\sclient\shttp.{0,1000}/ nocase ascii wide
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string19 = /.{0,1000}chisel\sserver\s\-.{0,1000}/ nocase ascii wide
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string20 = /.{0,1000}chisel\.exe\sclient.{0,1000}/ nocase ascii wide
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string21 = /.{0,1000}chisel\.exe\sserver.{0,1000}/ nocase ascii wide
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string22 = /.{0,1000}chisel\.jpillora\.com.{0,1000}/ nocase ascii wide
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string23 = /.{0,1000}chisel_1.{0,1000}_darwin_.{0,1000}\.gz.{0,1000}/ nocase ascii wide
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string24 = /.{0,1000}chisel_1.{0,1000}_linux_.{0,1000}\.gz.{0,1000}/ nocase ascii wide
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string25 = /.{0,1000}chisel_linux_amd64.{0,1000}/ nocase ascii wide
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string26 = /.{0,1000}chisel_windows_amd64\.exe.{0,1000}/ nocase ascii wide
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string27 = /.{0,1000}chisel\-master\.zip.{0,1000}/ nocase ascii wide
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string28 = /.{0,1000}jpillora\/chisel.{0,1000}/ nocase ascii wide
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string29 = /.{0,1000}\-local\=0\.0\.0\.0:4001.{0,1000}/ nocase ascii wide
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string30 = /.{0,1000}\-\-name\schisel\s\-p\s.{0,1000}/ nocase ascii wide
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string31 = /.{0,1000}\-remote\=127\.0\.0\.1:3000.{0,1000}/ nocase ascii wide
        // Description: A fast TCP/UDP tunnel over HTTP
        // Reference: https://github.com/jpillora/chisel
        $string32 = /.{0,1000}\-server\=http:\/\/127\.0\.0\.1:4002.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
