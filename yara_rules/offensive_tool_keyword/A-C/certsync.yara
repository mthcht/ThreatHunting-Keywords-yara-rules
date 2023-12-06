rule certsync
{
    meta:
        description = "Detection patterns for the tool 'certsync' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "certsync"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Dump NTDS with golden certificates and UnPAC the hash
        // Reference: https://github.com/zblurx/certsync
        $string1 = /\/certsync\.git/ nocase ascii wide
        // Description: Dump NTDS with golden certificates and UnPAC the hash
        // Reference: https://github.com/zblurx/certsync
        $string2 = /\\certipy\.pfx/ nocase ascii wide
        // Description: Dump NTDS with golden certificates and UnPAC the hash
        // Reference: https://github.com/zblurx/certsync
        $string3 = /\\Windows\\Tasks\\Certipy/ nocase ascii wide
        // Description: Dump NTDS with golden certificates and UnPAC the hash
        // Reference: https://github.com/zblurx/certsync
        $string4 = /certsync\s.{0,1000}\-\-dc\-ip/ nocase ascii wide
        // Description: Dump NTDS with golden certificates and UnPAC the hash
        // Reference: https://github.com/zblurx/certsync
        $string5 = /certsync\s\-u\s/ nocase ascii wide
        // Description: Dump NTDS with golden certificates and UnPAC the hash
        // Reference: https://github.com/zblurx/certsync
        $string6 = /certsync\-master\.zip/ nocase ascii wide
        // Description: Dump NTDS with golden certificates and UnPAC the hash
        // Reference: https://github.com/zblurx/certsync
        $string7 = /install\scertsync/ nocase ascii wide
        // Description: Dump NTDS with golden certificates and UnPAC the hash
        // Reference: https://github.com/zblurx/certsync
        $string8 = /zblurx\/certsync/ nocase ascii wide

    condition:
        any of them
}
