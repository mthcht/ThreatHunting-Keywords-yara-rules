rule Invoke_Obfuscation
{
    meta:
        description = "Detection patterns for the tool 'Invoke-Obfuscation' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Invoke-Obfuscation"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Invoke-Obfuscation is a PowerShell v2.0+ compatible PowerShell command and script obfuscator.
        // Reference: https://github.com/danielbohannon/Invoke-Obfuscation
        $string1 = /\\Obfuscated_Command\.txt/ nocase ascii wide
        // Description: Invoke-Obfuscation is a PowerShell v2.0+ compatible PowerShell command and script obfuscator.
        // Reference: https://github.com/danielbohannon/Invoke-Obfuscation
        $string2 = /Invoke\-Obfuscation/ nocase ascii wide

    condition:
        any of them
}
