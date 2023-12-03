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
        $string1 = /.{0,1000}\/certsync\.git.{0,1000}/ nocase ascii wide
        // Description: Dump NTDS with golden certificates and UnPAC the hash
        // Reference: https://github.com/zblurx/certsync
        $string2 = /.{0,1000}\\certipy\.pfx.{0,1000}/ nocase ascii wide
        // Description: Dump NTDS with golden certificates and UnPAC the hash
        // Reference: https://github.com/zblurx/certsync
        $string3 = /.{0,1000}\\Windows\\Tasks\\Certipy.{0,1000}/ nocase ascii wide
        // Description: Dump NTDS with golden certificates and UnPAC the hash
        // Reference: https://github.com/zblurx/certsync
        $string4 = /.{0,1000}certsync\s.{0,1000}\-\-dc\-ip.{0,1000}/ nocase ascii wide
        // Description: Dump NTDS with golden certificates and UnPAC the hash
        // Reference: https://github.com/zblurx/certsync
        $string5 = /.{0,1000}certsync\s\-u\s.{0,1000}/ nocase ascii wide
        // Description: Dump NTDS with golden certificates and UnPAC the hash
        // Reference: https://github.com/zblurx/certsync
        $string6 = /.{0,1000}certsync\-master\.zip.{0,1000}/ nocase ascii wide
        // Description: Dump NTDS with golden certificates and UnPAC the hash
        // Reference: https://github.com/zblurx/certsync
        $string7 = /.{0,1000}install\scertsync.{0,1000}/ nocase ascii wide
        // Description: Dump NTDS with golden certificates and UnPAC the hash
        // Reference: https://github.com/zblurx/certsync
        $string8 = /.{0,1000}zblurx\/certsync.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
