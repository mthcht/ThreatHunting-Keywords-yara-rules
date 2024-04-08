rule mimidogz
{
    meta:
        description = "Detection patterns for the tool 'mimidogz' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "mimidogz"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Rewrite of Invoke-Mimikatz.ps1 to avoid AV detection
        // Reference: https://github.com/projectb-temp/mimidogz
        $string1 = /\$ThisIsNotTheStringYouAreLookingFor/ nocase ascii wide
        // Description: Rewrite of Invoke-Mimikatz.ps1 to avoid AV detection
        // Reference: https://github.com/projectb-temp/mimidogz
        $string2 = /\/mimidogz\.git/ nocase ascii wide
        // Description: Rewrite of Invoke-Mimikatz.ps1 to avoid AV detection
        // Reference: https://github.com/projectb-temp/mimidogz
        $string3 = /\\mimidogz\-master/ nocase ascii wide
        // Description: Rewrite of Invoke-Mimikatz.ps1 to avoid AV detection
        // Reference: https://github.com/projectb-temp/mimidogz
        $string4 = /f2ee8facc06d5525d4bb73e079e8b599a0a2893351193013ba45ca311dbac50e/ nocase ascii wide
        // Description: Rewrite of Invoke-Mimikatz.ps1 to avoid AV detection
        // Reference: https://github.com/projectb-temp/mimidogz
        $string5 = /fir3d0g\/mimidogz/ nocase ascii wide
        // Description: Rewrite of Invoke-Mimikatz.ps1 to avoid AV detection
        // Reference: https://github.com/projectb-temp/mimidogz
        $string6 = /https\:\/\/www\.blackhillsinfosec\.com\/bypass\-anti\-virus\-run\-mimikatz/ nocase ascii wide
        // Description: Rewrite of Invoke-Mimikatz.ps1 to avoid AV detection
        // Reference: https://github.com/projectb-temp/mimidogz
        $string7 = /Invoke\-Dogz\.ps1/ nocase ascii wide
        // Description: Rewrite of Invoke-Mimikatz.ps1 to avoid AV detection
        // Reference: https://github.com/projectb-temp/mimidogz
        $string8 = /Invoke\-MimiDoggies/ nocase ascii wide
        // Description: Rewrite of Invoke-Mimikatz.ps1 to avoid AV detection
        // Reference: https://github.com/projectb-temp/mimidogz
        $string9 = /Invoke\-Mimidogz/ nocase ascii wide
        // Description: Rewrite of Invoke-Mimikatz.ps1 to avoid AV detection
        // Reference: https://github.com/projectb-temp/mimidogz
        $string10 = /Invoke\-Mimidogz\.ps1/ nocase ascii wide
        // Description: Rewrite of Invoke-Mimikatz.ps1 to avoid AV detection
        // Reference: https://github.com/projectb-temp/mimidogz
        $string11 = /mimidogz\-master\.zip/ nocase ascii wide
        // Description: Rewrite of Invoke-Mimikatz.ps1 to avoid AV detection
        // Reference: https://github.com/projectb-temp/mimidogz
        $string12 = /projectb\-temp\/mimidogz/ nocase ascii wide

    condition:
        any of them
}
