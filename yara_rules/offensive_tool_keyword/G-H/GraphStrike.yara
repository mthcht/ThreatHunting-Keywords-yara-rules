rule GraphStrike
{
    meta:
        description = "Detection patterns for the tool 'GraphStrike' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "GraphStrike"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Cobalt Strike HTTPS beaconing over Microsoft Graph API
        // Reference: https://github.com/RedSiege/GraphStrike
        $string1 = /\sGraphStrike\.py/ nocase ascii wide
        // Description: Cobalt Strike HTTPS beaconing over Microsoft Graph API
        // Reference: https://github.com/RedSiege/GraphStrike
        $string2 = /\.cobaltstrike\.beacon_keys/ nocase ascii wide
        // Description: Cobalt Strike HTTPS beaconing over Microsoft Graph API
        // Reference: https://github.com/RedSiege/GraphStrike
        $string3 = /\/GraphStrike\.cna/ nocase ascii wide
        // Description: Cobalt Strike HTTPS beaconing over Microsoft Graph API
        // Reference: https://github.com/RedSiege/GraphStrike
        $string4 = /\/GraphStrike\.git/ nocase ascii wide
        // Description: Cobalt Strike HTTPS beaconing over Microsoft Graph API
        // Reference: https://github.com/RedSiege/GraphStrike
        $string5 = /\/graphstrike\.profile/ nocase ascii wide
        // Description: Cobalt Strike HTTPS beaconing over Microsoft Graph API
        // Reference: https://github.com/RedSiege/GraphStrike
        $string6 = /\/GraphStrike\.py/ nocase ascii wide
        // Description: Cobalt Strike HTTPS beaconing over Microsoft Graph API
        // Reference: https://github.com/RedSiege/GraphStrike
        $string7 = /\/GraphStrike\-main\// nocase ascii wide
        // Description: Cobalt Strike HTTPS beaconing over Microsoft Graph API
        // Reference: https://github.com/RedSiege/GraphStrike
        $string8 = /\/opt\/cobaltstrike\// nocase ascii wide
        // Description: Cobalt Strike HTTPS beaconing over Microsoft Graph API
        // Reference: https://github.com/RedSiege/GraphStrike
        $string9 = /\[\+\]\sRandomizing\ssyscall\snames/ nocase ascii wide
        // Description: Cobalt Strike HTTPS beaconing over Microsoft Graph API
        // Reference: https://github.com/RedSiege/GraphStrike
        $string10 = /\[\+\]\sUsing\sdomain\senumeration\sfor\ssandbox\sevasion/ nocase ascii wide
        // Description: Cobalt Strike HTTPS beaconing over Microsoft Graph API
        // Reference: https://github.com/RedSiege/GraphStrike
        $string11 = /\\GraphLdr\.x64\.bin/ nocase ascii wide
        // Description: Cobalt Strike HTTPS beaconing over Microsoft Graph API
        // Reference: https://github.com/RedSiege/GraphStrike
        $string12 = /\\GraphStrike\.cna/ nocase ascii wide
        // Description: Cobalt Strike HTTPS beaconing over Microsoft Graph API
        // Reference: https://github.com/RedSiege/GraphStrike
        $string13 = /\\GraphStrike\.py/ nocase ascii wide
        // Description: Cobalt Strike HTTPS beaconing over Microsoft Graph API
        // Reference: https://github.com/RedSiege/GraphStrike
        $string14 = /\\GraphStrike\-main\\/ nocase ascii wide
        // Description: Cobalt Strike HTTPS beaconing over Microsoft Graph API
        // Reference: https://github.com/RedSiege/GraphStrike
        $string15 = /change_sandbox_evasion_method\(/ nocase ascii wide
        // Description: Cobalt Strike HTTPS beaconing over Microsoft Graph API
        // Reference: https://github.com/RedSiege/GraphStrike
        $string16 = /GraphLdr\.x64\.bin/ nocase ascii wide
        // Description: Cobalt Strike HTTPS beaconing over Microsoft Graph API
        // Reference: https://github.com/RedSiege/GraphStrike
        $string17 = /GraphLdr\.x64\.exe/ nocase ascii wide
        // Description: Cobalt Strike HTTPS beaconing over Microsoft Graph API
        // Reference: https://github.com/RedSiege/GraphStrike
        $string18 = /GraphStrike\sServer\sis\srunning\sand\schecking\sSharePoint\sfor\sBeacon\straffic/ nocase ascii wide
        // Description: Cobalt Strike HTTPS beaconing over Microsoft Graph API
        // Reference: https://github.com/RedSiege/GraphStrike
        $string19 = /GraphStrike\.py\s/ nocase ascii wide
        // Description: Cobalt Strike HTTPS beaconing over Microsoft Graph API
        // Reference: https://github.com/RedSiege/GraphStrike
        $string20 = /Lost\sconnection\sto\steam\sserver\!\sSleeping\s60\ssecond\sand\sretrying\?/ nocase ascii wide
        // Description: Cobalt Strike HTTPS beaconing over Microsoft Graph API
        // Reference: https://github.com/RedSiege/GraphStrike
        $string21 = /RedSiege\/GraphStrike/ nocase ascii wide

    condition:
        any of them
}
