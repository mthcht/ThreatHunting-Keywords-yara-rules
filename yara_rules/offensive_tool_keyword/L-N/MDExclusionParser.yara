rule MDExclusionParser
{
    meta:
        description = "Detection patterns for the tool 'MDExclusionParser' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "MDExclusionParser"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: PowerShell script to quickly scan Event Log ID 5007 and 1121 for published Windows Defender Exclusions and Attack Surface Reduction (ASR) rule configuration.
        // Reference: https://github.com/ViziosDe/MDExclusionParser
        $string1 = /\sInvoke\-MDExclusionParser\.ps1/ nocase ascii wide
        // Description: PowerShell script to quickly scan Event Log ID 5007 and 1121 for published Windows Defender Exclusions and Attack Surface Reduction (ASR) rule configuration.
        // Reference: https://github.com/ViziosDe/MDExclusionParser
        $string2 = /\/Invoke\-MDExclusionParser\.ps1/ nocase ascii wide
        // Description: PowerShell script to quickly scan Event Log ID 5007 and 1121 for published Windows Defender Exclusions and Attack Surface Reduction (ASR) rule configuration.
        // Reference: https://github.com/ViziosDe/MDExclusionParser
        $string3 = /\/MDExclusionParser\.git/ nocase ascii wide
        // Description: PowerShell script to quickly scan Event Log ID 5007 and 1121 for published Windows Defender Exclusions and Attack Surface Reduction (ASR) rule configuration.
        // Reference: https://github.com/ViziosDe/MDExclusionParser
        $string4 = /\[i\]\sParsing\sfor\sDefender\sExclusions/ nocase ascii wide
        // Description: PowerShell script to quickly scan Event Log ID 5007 and 1121 for published Windows Defender Exclusions and Attack Surface Reduction (ASR) rule configuration.
        // Reference: https://github.com/ViziosDe/MDExclusionParser
        $string5 = /\\Invoke\-MDExclusionParser\.ps1/ nocase ascii wide
        // Description: PowerShell script to quickly scan Event Log ID 5007 and 1121 for published Windows Defender Exclusions and Attack Surface Reduction (ASR) rule configuration.
        // Reference: https://github.com/ViziosDe/MDExclusionParser
        $string6 = "Invoke-MDExclusionParser " nocase ascii wide
        // Description: PowerShell script to quickly scan Event Log ID 5007 and 1121 for published Windows Defender Exclusions and Attack Surface Reduction (ASR) rule configuration.
        // Reference: https://github.com/ViziosDe/MDExclusionParser
        $string7 = "MDExclusionParser-main" nocase ascii wide
        // Description: PowerShell script to quickly scan Event Log ID 5007 and 1121 for published Windows Defender Exclusions and Attack Surface Reduction (ASR) rule configuration.
        // Reference: https://github.com/ViziosDe/MDExclusionParser
        $string8 = "ViziosDe/MDExclusionParser" nocase ascii wide

    condition:
        any of them
}
