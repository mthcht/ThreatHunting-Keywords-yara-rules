rule kali_anonsurf
{
    meta:
        description = "Detection patterns for the tool 'kali-anonsurf' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "kali-anonsurf"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Anonsurf will anonymize the entire system under TOR using IPTables. It will also allow you to start and stop i2p as well.
        // Reference: https://github.com/Und3rf10w/kali-anonsurf
        $string1 = /kali\-anonsurf/ nocase ascii wide

    condition:
        any of them
}
