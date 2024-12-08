rule Powersploit
{
    meta:
        description = "Detection patterns for the tool 'Powersploit' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Powersploit"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: PowerSploit contains a PowerShell script which utilizes the volume shadow copy service to create a new volume that could be used for extraction of files
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string1 = "Get-VolumeShadowCopy " nocase ascii wide
        // Description: PowerSploit contains a PowerShell script which utilizes the volume shadow copy service to create a new volume that could be used for extraction of files
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string2 = /New\-VolumeShadowCopy\s\-Volume\sC\:\\/ nocase ascii wide
        // Description: PowerSploit contains a PowerShell script which utilizes the volume shadow copy service to create a new volume that could be used for extraction of files
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string3 = /VolumeShadowCopyTools\.ps1/ nocase ascii wide

    condition:
        any of them
}
