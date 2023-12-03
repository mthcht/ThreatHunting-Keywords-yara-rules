rule nysm
{
    meta:
        description = "Detection patterns for the tool 'nysm' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "nysm"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: nysm is a stealth post-exploitation container
        // Reference: https://github.com/eeriedusk/nysm
        $string1 = /.{0,1000}\.\/nysm\/src\// nocase ascii wide
        // Description: nysm is a stealth post-exploitation container
        // Reference: https://github.com/eeriedusk/nysm
        $string2 = /.{0,1000}\/nysm\sbash.{0,1000}/ nocase ascii wide
        // Description: nysm is a stealth post-exploitation container
        // Reference: https://github.com/eeriedusk/nysm
        $string3 = /.{0,1000}\/nysm\s\-dr\ssocat\sTCP4\-LISTEN.{0,1000}/ nocase ascii wide
        // Description: nysm is a stealth post-exploitation container
        // Reference: https://github.com/eeriedusk/nysm
        $string4 = /.{0,1000}\/nysm\s\-r\sssh\s.{0,1000}\@.{0,1000}/ nocase ascii wide
        // Description: nysm is a stealth post-exploitation container
        // Reference: https://github.com/eeriedusk/nysm
        $string5 = /.{0,1000}\/nysm\.bpf\.c.{0,1000}/ nocase ascii wide
        // Description: nysm is a stealth post-exploitation container
        // Reference: https://github.com/eeriedusk/nysm
        $string6 = /.{0,1000}\/nysm\.git.{0,1000}/ nocase ascii wide
        // Description: nysm is a stealth post-exploitation container
        // Reference: https://github.com/eeriedusk/nysm
        $string7 = /.{0,1000}\/src\/nysm\.c.{0,1000}/ nocase ascii wide
        // Description: nysm is a stealth post-exploitation container
        // Reference: https://github.com/eeriedusk/nysm
        $string8 = /.{0,1000}eeriedusk\/nysm.{0,1000}/ nocase ascii wide
        // Description: nysm is a stealth post-exploitation container
        // Reference: https://github.com/eeriedusk/nysm
        $string9 = /.{0,1000}nysm\.skel\.h.{0,1000}/ nocase ascii wide
        // Description: nysm is a stealth post-exploitation container
        // Reference: https://github.com/eeriedusk/nysm
        $string10 = /.{0,1000}nysm\-master\.zip.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
