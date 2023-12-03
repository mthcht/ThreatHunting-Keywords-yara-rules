rule bitb
{
    meta:
        description = "Detection patterns for the tool 'bitb' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "bitb"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Browser templates for Browser In The Browser (BITB) attack
        // Reference: https://github.com/mrd0x/BITB
        $string1 = /.{0,1000}\/BITB\.git.{0,1000}/ nocase ascii wide
        // Description: Browser templates for Browser In The Browser (BITB) attack
        // Reference: https://github.com/mrd0x/BITB
        $string2 = /.{0,1000}\/BITB\-main.{0,1000}/ nocase ascii wide
        // Description: Browser templates for Browser In The Browser (BITB) attack
        // Reference: https://github.com/mrd0x/BITB
        $string3 = /.{0,1000}\\BITB\-main.{0,1000}/ nocase ascii wide
        // Description: Browser templates for Browser In The Browser (BITB) attack
        // Reference: https://github.com/mrd0x/BITB
        $string4 = /.{0,1000}bitb_server\/phishing\.ini.{0,1000}/ nocase ascii wide
        // Description: Browser templates for Browser In The Browser (BITB) attack
        // Reference: https://github.com/mrd0x/BITB
        $string5 = /.{0,1000}mrd0x\/BITB.{0,1000}/ nocase ascii wide
        // Description: Browser templates for Browser In The Browser (BITB) attack
        // Reference: https://github.com/mrd0x/BITB
        $string6 = /.{0,1000}XX\-PHISHING\-LINK\-XX.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
