rule Invoke_AzureEnum
{
    meta:
        description = "Detection patterns for the tool 'Invoke-AzureEnum' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Invoke-AzureEnum"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: This cmdlet is used to perform users enumeration against Azure
        // Reference: https://github.com/tobor88/PowerShell-Red-Team/blob/master/Invoke-AzureEnum.ps1
        $string1 = /Invoke\-AzureEnum\.ps1/ nocase ascii wide

    condition:
        any of them
}
