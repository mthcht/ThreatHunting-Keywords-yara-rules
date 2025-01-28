rule rustcat
{
    meta:
        description = "Detection patterns for the tool 'rustcat' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "rustcat"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Rustcat(rcat) - The modern Port listener and Reverse shell
        // Reference: https://github.com/robiot/rustcat
        $string1 = /\/bin\/bash\s\-c\s\'bash\s\-i\s\>\&\s\/dev\/tcp\/.{0,1000}\/.{0,1000}\s0\>\&1\'/
        // Description: Rustcat(rcat) - The modern Port listener and Reverse shell
        // Reference: https://github.com/robiot/rustcat
        $string2 = /\/rcat\-v.{0,1000}\-win\-x86_64\.exe/ nocase ascii wide
        // Description: Rustcat(rcat) - The modern Port listener and Reverse shell
        // Reference: https://github.com/robiot/rustcat
        $string3 = "/rustcat/releases/latest/download/" nocase ascii wide
        // Description: Rustcat(rcat) - The modern Port listener and Reverse shell
        // Reference: https://github.com/robiot/rustcat
        $string4 = /\/src\/unixshell\.rs/ nocase ascii wide
        // Description: Rustcat(rcat) - The modern Port listener and Reverse shell
        // Reference: https://github.com/robiot/rustcat
        $string5 = /\\rcat\-v.{0,1000}\-win\-x86_64\.exe/ nocase ascii wide
        // Description: Rustcat(rcat) - The modern Port listener and Reverse shell
        // Reference: https://github.com/robiot/rustcat
        $string6 = "B473B9A4135DE247C6D76510B40F63F8F1E5A2AB" nocase ascii wide
        // Description: Rustcat(rcat) - The modern Port listener and Reverse shell
        // Reference: https://github.com/robiot/rustcat
        $string7 = "blackarch/tree/master/packages/rustcat" nocase ascii wide
        // Description: Rustcat(rcat) - The modern Port listener and Reverse shell
        // Reference: https://github.com/robiot/rustcat
        $string8 = "pacman -S rustcat" nocase ascii wide
        // Description: Rustcat(rcat) - The modern Port listener and Reverse shell
        // Reference: https://github.com/robiot/rustcat
        $string9 = "rcan listen -ib " nocase ascii wide
        // Description: Rustcat(rcat) - The modern Port listener and Reverse shell
        // Reference: https://github.com/robiot/rustcat
        $string10 = "rcat c -s bash "
        // Description: Rustcat(rcat) - The modern Port listener and Reverse shell
        // Reference: https://github.com/robiot/rustcat
        $string11 = "rcat connect -s bash"
        // Description: Rustcat(rcat) - The modern Port listener and Reverse shell
        // Reference: https://github.com/robiot/rustcat
        $string12 = "rcat listen 55660" nocase ascii wide
        // Description: Rustcat(rcat) - The modern Port listener and Reverse shell
        // Reference: https://github.com/robiot/rustcat
        $string13 = "rcat listen -ie " nocase ascii wide
        // Description: Rustcat(rcat) - The modern Port listener and Reverse shell
        // Reference: https://github.com/robiot/rustcat
        $string14 = "rcat listen -l " nocase ascii wide
        // Description: Rustcat(rcat) - The modern Port listener and Reverse shell
        // Reference: https://github.com/robiot/rustcat
        $string15 = /rcat\-v3\..{0,1000}darwin\-aarch64/
        // Description: Rustcat(rcat) - The modern Port listener and Reverse shell
        // Reference: https://github.com/robiot/rustcat
        $string16 = /rcat\-v3\..{0,1000}\-darwin\-x86_64/
        // Description: Rustcat(rcat) - The modern Port listener and Reverse shell
        // Reference: https://github.com/robiot/rustcat
        $string17 = /rcat\-v3\..{0,1000}\-linux\-x86_64/
        // Description: Rustcat(rcat) - The modern Port listener and Reverse shell
        // Reference: https://github.com/robiot/rustcat
        $string18 = /rustcat\-3\.0\.0\.zip/ nocase ascii wide
        // Description: Rustcat(rcat) - The modern Port listener and Reverse shell
        // Reference: https://github.com/robiot/rustcat
        $string19 = "rcat listen " nocase ascii wide

    condition:
        any of them
}
