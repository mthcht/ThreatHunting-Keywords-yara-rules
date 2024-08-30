rule MEGAcmd
{
    meta:
        description = "Detection patterns for the tool 'MEGAcmd' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "MEGAcmd"
        rule_category = "signature_keyword"

    strings:
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string1 = /Hacktool\.MEGAclient/ nocase ascii wide

    condition:
        any of them
}
