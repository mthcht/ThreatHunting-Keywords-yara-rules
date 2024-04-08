rule regsvr32
{
    meta:
        description = "Detection patterns for the tool 'regsvr32' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "regsvr32"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: A fake AMSI Provider which can be used for persistence
        // Reference: https://github.com/netbiosX/AMSI-Provider
        $string1 = /regsvr32\sAmsiProvider\.dll/ nocase ascii wide

    condition:
        any of them
}
