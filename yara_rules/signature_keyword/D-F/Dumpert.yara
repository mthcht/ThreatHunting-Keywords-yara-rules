rule Dumpert
{
    meta:
        description = "Detection patterns for the tool 'Dumpert' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Dumpert"
        rule_category = "signature_keyword"

    strings:
        // Description: Dumpert. an LSASS memory dumper using direct system calls and API unhooking Recent malware research shows that there is an increase in malware that is using direct system calls to evade user-mode API hooks used by security products. This tool demonstrates the use of direct System Calls and API unhooking and combine these techniques in a proof of concept code which can be used to create a LSASS memory dump using Cobalt Strike. while not touching disk and evading AV/EDR monitored user-mode API calls.
        // Reference: https://github.com/outflanknl/Dumpert
        $string1 = "Win64/Outflank" nocase ascii wide

    condition:
        any of them
}
