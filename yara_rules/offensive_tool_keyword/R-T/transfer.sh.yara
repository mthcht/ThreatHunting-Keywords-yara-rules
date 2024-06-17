rule transfer_sh
{
    meta:
        description = "Detection patterns for the tool 'transfer.sh' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "transfer.sh"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Downloading pdf  from transfer.sh
        // Reference: https://medium.com/checkmarx-security/python-obfuscation-traps-1acced941375
        $string1 = /https\:\/\/transfer\.sh\/get\/.{0,1000}\/.{0,1000}\.pdf/ nocase ascii wide
        // Description: Downloading python scripts from transfer.sh
        // Reference: https://medium.com/checkmarx-security/python-obfuscation-traps-1acced941375
        $string2 = /https\:\/\/transfer\.sh\/get\/.{0,1000}\/.{0,1000}\.py/ nocase ascii wide

    condition:
        any of them
}
