rule Timeroast
{
    meta:
        description = "Detection patterns for the tool 'Timeroast' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Timeroast"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Timeroasting takes advantage of Windows NTP authentication mechanism allowing unauthenticated attackers to effectively request a password hash of any computer or trust account by sending an NTP request with that account's RID
        // Reference: https://github.com/SecuraBV/Timeroast
        $string1 = /.{0,1000}extra\-scripts.{0,1000}timecrack\.py.{0,1000}/ nocase ascii wide
        // Description: Timeroasting takes advantage of Windows NTP authentication mechanism allowing unauthenticated attackers to effectively request a password hash of any computer or trust account by sending an NTP request with that account's RID
        // Reference: https://github.com/SecuraBV/Timeroast
        $string2 = /.{0,1000}kirbi_to_hashcat\.py.{0,1000}/ nocase ascii wide
        // Description: Timeroasting takes advantage of Windows NTP authentication mechanism allowing unauthenticated attackers to effectively request a password hash of any computer or trust account by sending an NTP request with that account's RID
        // Reference: https://github.com/SecuraBV/Timeroast
        $string3 = /.{0,1000}timeroast\.ps1.{0,1000}/ nocase ascii wide
        // Description: Timeroasting takes advantage of Windows NTP authentication mechanism allowing unauthenticated attackers to effectively request a password hash of any computer or trust account by sending an NTP request with that account's RID
        // Reference: https://github.com/SecuraBV/Timeroast
        $string4 = /.{0,1000}timeroast\.py.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
