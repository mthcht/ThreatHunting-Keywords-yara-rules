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
        $string1 = /\/BITB\.git/ nocase ascii wide
        // Description: Browser templates for Browser In The Browser (BITB) attack
        // Reference: https://github.com/mrd0x/BITB
        $string2 = /\/BITB\-main/ nocase ascii wide
        // Description: Browser templates for Browser In The Browser (BITB) attack
        // Reference: https://github.com/mrd0x/BITB
        $string3 = /\\BITB\-main/ nocase ascii wide
        // Description: Browser templates for Browser In The Browser (BITB) attack
        // Reference: https://github.com/mrd0x/BITB
        $string4 = /bitb_server\/phishing\.ini/ nocase ascii wide
        // Description: Browser templates for Browser In The Browser (BITB) attack
        // Reference: https://github.com/mrd0x/BITB
        $string5 = /mrd0x\/BITB/ nocase ascii wide
        // Description: Browser templates for Browser In The Browser (BITB) attack
        // Reference: https://github.com/mrd0x/BITB
        $string6 = /XX\-PHISHING\-LINK\-XX/ nocase ascii wide

    condition:
        any of them
}
