rule AzureAD_Autologon_Brute
{
    meta:
        description = "Detection patterns for the tool 'AzureAD_Autologon_Brute' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "AzureAD_Autologon_Brute"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Brute force attack tool for Azure AD Autologon
        // Reference: https://github.com/nyxgeek/AzureAD_Autologon_Brute
        $string1 = /AzureAD\sAutoLogon\sBrute/ nocase ascii wide
        // Description: Brute force attack tool for Azure AD Autologon
        // Reference: https://github.com/nyxgeek/AzureAD_Autologon_Brute
        $string2 = /AzureAD_Autologon_Brute/ nocase ascii wide

    condition:
        any of them
}
