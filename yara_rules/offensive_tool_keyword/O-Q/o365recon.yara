rule o365recon
{
    meta:
        description = "Detection patterns for the tool 'o365recon' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "o365recon"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: script to retrieve information via O365 and AzureAD with a valid cred 
        // Reference: https://github.com/nyxgeek/o365recon
        $string1 = /\/o365recon/ nocase ascii wide
        // Description: script to retrieve information via O365 and AzureAD with a valid cred 
        // Reference: https://github.com/nyxgeek/o365recon
        $string2 = /\\.{0,1000}\.O365\.GroupMembership_AdminGroups\.txt/ nocase ascii wide
        // Description: script to retrieve information via O365 and AzureAD with a valid cred 
        // Reference: https://github.com/nyxgeek/o365recon
        $string3 = /\\.{0,1000}\.O365\.GroupMembership_VPNGroups\.txt/ nocase ascii wide
        // Description: script to retrieve information via O365 and AzureAD with a valid cred 
        // Reference: https://github.com/nyxgeek/o365recon
        $string4 = /\\.{0,1000}\.O365\.Roles_Admins\.txt/ nocase ascii wide
        // Description: script to retrieve information via O365 with a valid cred
        // Reference: https://github.com/nyxgeek/o365recon
        $string5 = /o365recon/ nocase ascii wide
        // Description: script to retrieve information via O365 and AzureAD with a valid cred 
        // Reference: https://github.com/nyxgeek/o365recon
        $string6 = /o365recon\.git/ nocase ascii wide
        // Description: script to retrieve information via O365 and AzureAD with a valid cred 
        // Reference: https://github.com/nyxgeek/o365recon
        $string7 = /o365recon\.ps1/ nocase ascii wide
        // Description: script to retrieve information via O365 and AzureAD with a valid cred 
        // Reference: https://github.com/nyxgeek/o365recon
        $string8 = /o365recon\-master/ nocase ascii wide

    condition:
        any of them
}
