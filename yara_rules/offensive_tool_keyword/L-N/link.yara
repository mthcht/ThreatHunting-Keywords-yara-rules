rule link
{
    meta:
        description = "Detection patterns for the tool 'link' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "link"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: link is a command and control framework written in rust
        // Reference: https://github.com/postrequest/link
        $string1 = /\skali\-install\.sh/ nocase ascii wide
        // Description: link is a command and control framework written in rust
        // Reference: https://github.com/postrequest/link
        $string2 = /\.\/kali\-install\.sh/ nocase ascii wide
        // Description: link is a command and control framework written in rust
        // Reference: https://github.com/postrequest/link
        $string3 = /\.link\/links\/windows\/target\/x86_64\-pc\-windows\-gnu\/release\/link\.exe/ nocase ascii wide
        // Description: link is a command and control framework written in rust
        // Reference: https://github.com/postrequest/link
        $string4 = /\/\.link\/3rdparty\/SharpCollection/ nocase ascii wide
        // Description: link is a command and control framework written in rust
        // Reference: https://github.com/postrequest/link
        $string5 = /\/Stracciatella\/releases\/latest\/download\/Stracciatella\.exe/ nocase ascii wide
        // Description: link is a command and control framework written in rust
        // Reference: https://github.com/postrequest/link
        $string6 = /\\kali\-install\.sh/ nocase ascii wide
        // Description: link is a command and control framework written in rust
        // Reference: https://github.com/postrequest/link
        $string7 = /\\src\\links\\windows\\src\\evasion\.rs/ nocase ascii wide
        // Description: link is a command and control framework written in rust
        // Reference: https://github.com/postrequest/link
        $string8 = /execute\sPowerShell\swithout\spowershell\.exe/ nocase ascii wide
        // Description: link is a command and control framework written in rust
        // Reference: https://github.com/postrequest/link
        $string9 = /execute\-assembly\ssvchost\s.{0,1000}\.exe/ nocase ascii wide
        // Description: link is a command and control framework written in rust
        // Reference: https://github.com/postrequest/link
        $string10 = /execute\-pe\ssvchost\swhoami\.exe/ nocase ascii wide
        // Description: link is a command and control framework written in rust
        // Reference: https://github.com/postrequest/link
        $string11 = /github\.com\/postrequest\/link/ nocase ascii wide
        // Description: link is a command and control framework written in rust
        // Reference: https://github.com/postrequest/link
        $string12 = /link\-inject.{0,1000}inject\slink\sinto\sprocess/ nocase ascii wide
        // Description: link is a command and control framework written in rust
        // Reference: https://github.com/postrequest/link
        $string13 = /Out\-Minidump\.ps1/ nocase ascii wide
        // Description: link is a command and control framework written in rust
        // Reference: https://github.com/postrequest/link
        $string14 = /output\:\slink\.bin/ nocase ascii wide
        // Description: link is a command and control framework written in rust
        // Reference: https://github.com/postrequest/link
        $string15 = /output\:\slink\.dll/ nocase ascii wide
        // Description: link is a command and control framework written in rust
        // Reference: https://github.com/postrequest/link
        $string16 = "pip3 install pypykatz" nocase ascii wide
        // Description: link is a command and control framework written in rust
        // Reference: https://github.com/postrequest/link
        $string17 = /postrequest\/link\.git/ nocase ascii wide
        // Description: link is a command and control framework written in rust
        // Reference: https://github.com/postrequest/link
        $string18 = "pypykatz not installed" nocase ascii wide
        // Description: link is a command and control framework written in rust
        // Reference: https://github.com/postrequest/link
        $string19 = "sharp ADCollector" nocase ascii wide
        // Description: link is a command and control framework written in rust
        // Reference: https://github.com/postrequest/link
        $string20 = "sharp ADSearch" nocase ascii wide
        // Description: link is a command and control framework written in rust
        // Reference: https://github.com/postrequest/link
        $string21 = "sharp BetterSafetyKatz" nocase ascii wide
        // Description: link is a command and control framework written in rust
        // Reference: https://github.com/postrequest/link
        $string22 = "sharp init  download/update SharpCollection tools" nocase ascii wide
        // Description: link is a command and control framework written in rust
        // Reference: https://github.com/postrequest/link
        $string23 = "sharp InveighZero" nocase ascii wide
        // Description: link is a command and control framework written in rust
        // Reference: https://github.com/postrequest/link
        $string24 = "sharp SharpAllowedToAct" nocase ascii wide
        // Description: link is a command and control framework written in rust
        // Reference: https://github.com/postrequest/link
        $string25 = "sharp SharpAppLocker" nocase ascii wide
        // Description: link is a command and control framework written in rust
        // Reference: https://github.com/postrequest/link
        $string26 = "sharp SharpChisel" nocase ascii wide
        // Description: link is a command and control framework written in rust
        // Reference: https://github.com/postrequest/link
        $string27 = "sharp SharpChromium" nocase ascii wide
        // Description: link is a command and control framework written in rust
        // Reference: https://github.com/postrequest/link
        $string28 = "sharp SharpCrashEventLog " nocase ascii wide
        // Description: link is a command and control framework written in rust
        // Reference: https://github.com/postrequest/link
        $string29 = "sharp SharpKatz --Command logonpasswords" nocase ascii wide
        // Description: link is a command and control framework written in rust
        // Reference: https://github.com/postrequest/link
        $string30 = "sharp SharpMiniDump" nocase ascii wide
        // Description: link is a command and control framework written in rust
        // Reference: https://github.com/postrequest/link
        $string31 = "sharp Sharp-SMBExec " nocase ascii wide
        // Description: link is a command and control framework written in rust
        // Reference: https://github.com/postrequest/link
        $string32 = "sharp SharpSpray" nocase ascii wide
        // Description: link is a command and control framework written in rust
        // Reference: https://github.com/postrequest/link
        $string33 = "sharp SharpZeroLogon" nocase ascii wide
        // Description: link is a command and control framework written in rust
        // Reference: https://github.com/postrequest/link
        $string34 = "sharp StickyNotesExtract" nocase ascii wide
        // Description: link is a command and control framework written in rust
        // Reference: https://github.com/postrequest/link
        $string35 = "sharp winPEAS" nocase ascii wide
        // Description: link is a command and control framework written in rust
        // Reference: https://github.com/postrequest/link
        $string36 = /sharp_collection\.insert\(/ nocase ascii wide
        // Description: link is a command and control framework written in rust
        // Reference: https://github.com/postrequest/link
        $string37 = /SharpKatz\.exe/ nocase ascii wide

    condition:
        any of them
}
