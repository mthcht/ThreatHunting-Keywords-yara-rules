rule RemoteUtilities
{
    meta:
        description = "Detection patterns for the tool 'RemoteUtilities' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RemoteUtilities"
        rule_category = "signature_keyword"

    strings:
        // Description: RemoteUtilities Remote Access softwares
        // Reference: https://www.remoteutilities.com/
        $string1 = /RemoteAdmin\.RemoteUtilities/ nocase ascii wide
        // Description: RemoteUtilities Remote Access softwares
        // Reference: https://www.remoteutilities.com/
        $string2 = /Trojan\.RemoteUtilitiesRAT/ nocase ascii wide

    condition:
        any of them
}
