rule Invoke_AzurePasswordSpray
{
    meta:
        description = "Detection patterns for the tool 'Invoke-AzurePasswordSpray' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Invoke-AzurePasswordSpray"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: This cmdlet is used to perform a password spray attack against Azure accounts using legacy Basic Authentication
        // Reference: https://github.com/tobor88/PowerShell-Red-Team/blob/master/Invoke-AzurePasswordSpray.ps1
        $string1 = /Invoke\-AzurePasswordSpray/ nocase ascii wide

    condition:
        any of them
}
