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
        $string16 = /pip3\sinstall\spypykatz/ nocase ascii wide
        // Description: link is a command and control framework written in rust
        // Reference: https://github.com/postrequest/link
        $string17 = /postrequest\/link\.git/ nocase ascii wide
        // Description: link is a command and control framework written in rust
        // Reference: https://github.com/postrequest/link
        $string18 = /pypykatz\snot\sinstalled/ nocase ascii wide
        // Description: link is a command and control framework written in rust
        // Reference: https://github.com/postrequest/link
        $string19 = /sharp\sADCollector/ nocase ascii wide
        // Description: link is a command and control framework written in rust
        // Reference: https://github.com/postrequest/link
        $string20 = /sharp\sADSearch/ nocase ascii wide
        // Description: link is a command and control framework written in rust
        // Reference: https://github.com/postrequest/link
        $string21 = /sharp\sBetterSafetyKatz/ nocase ascii wide
        // Description: link is a command and control framework written in rust
        // Reference: https://github.com/postrequest/link
        $string22 = /sharp\sinit\s\sdownload\/update\sSharpCollection\stools/ nocase ascii wide
        // Description: link is a command and control framework written in rust
        // Reference: https://github.com/postrequest/link
        $string23 = /sharp\sInveighZero/ nocase ascii wide
        // Description: link is a command and control framework written in rust
        // Reference: https://github.com/postrequest/link
        $string24 = /sharp\sSharpAllowedToAct/ nocase ascii wide
        // Description: link is a command and control framework written in rust
        // Reference: https://github.com/postrequest/link
        $string25 = /sharp\sSharpAppLocker/ nocase ascii wide
        // Description: link is a command and control framework written in rust
        // Reference: https://github.com/postrequest/link
        $string26 = /sharp\sSharpChisel/ nocase ascii wide
        // Description: link is a command and control framework written in rust
        // Reference: https://github.com/postrequest/link
        $string27 = /sharp\sSharpChromium/ nocase ascii wide
        // Description: link is a command and control framework written in rust
        // Reference: https://github.com/postrequest/link
        $string28 = /sharp\sSharpCrashEventLog\s/ nocase ascii wide
        // Description: link is a command and control framework written in rust
        // Reference: https://github.com/postrequest/link
        $string29 = /sharp\sSharpKatz\s\-\-Command\slogonpasswords/ nocase ascii wide
        // Description: link is a command and control framework written in rust
        // Reference: https://github.com/postrequest/link
        $string30 = /sharp\sSharpMiniDump/ nocase ascii wide
        // Description: link is a command and control framework written in rust
        // Reference: https://github.com/postrequest/link
        $string31 = /sharp\sSharp\-SMBExec\s/ nocase ascii wide
        // Description: link is a command and control framework written in rust
        // Reference: https://github.com/postrequest/link
        $string32 = /sharp\sSharpSpray/ nocase ascii wide
        // Description: link is a command and control framework written in rust
        // Reference: https://github.com/postrequest/link
        $string33 = /sharp\sSharpZeroLogon/ nocase ascii wide
        // Description: link is a command and control framework written in rust
        // Reference: https://github.com/postrequest/link
        $string34 = /sharp\sStickyNotesExtract/ nocase ascii wide
        // Description: link is a command and control framework written in rust
        // Reference: https://github.com/postrequest/link
        $string35 = /sharp\swinPEAS/ nocase ascii wide
        // Description: link is a command and control framework written in rust
        // Reference: https://github.com/postrequest/link
        $string36 = /sharp_collection\.insert\(/ nocase ascii wide
        // Description: link is a command and control framework written in rust
        // Reference: https://github.com/postrequest/link
        $string37 = /SharpKatz\.exe/ nocase ascii wide

    condition:
        any of them
}
