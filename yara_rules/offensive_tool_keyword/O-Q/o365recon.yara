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
        $string1 = /\.AzureAD\.Application_Owners\.csv/ nocase ascii wide
        // Description: script to retrieve information via O365 and AzureAD with a valid cred 
        // Reference: https://github.com/nyxgeek/o365recon
        $string2 = /\.AzureAD\.DeviceList_Owners\.csv/ nocase ascii wide
        // Description: script to retrieve information via O365 and AzureAD with a valid cred 
        // Reference: https://github.com/nyxgeek/o365recon
        $string3 = /\.O365\.GroupMembership_AdminGroups\.txt/ nocase ascii wide
        // Description: script to retrieve information via O365 and AzureAD with a valid cred 
        // Reference: https://github.com/nyxgeek/o365recon
        $string4 = /\.O365\.GroupMembership_VPNGroups\.txt/ nocase ascii wide
        // Description: script to retrieve information via O365 and AzureAD with a valid cred 
        // Reference: https://github.com/nyxgeek/o365recon
        $string5 = /\.O365\.Roles_Admins\.txt/ nocase ascii wide
        // Description: script to retrieve information via O365 and AzureAD with a valid cred 
        // Reference: https://github.com/nyxgeek/o365recon
        $string6 = /\.O365\.Users_Detailed\.csv/ nocase ascii wide
        // Description: script to retrieve information via O365 and AzureAD with a valid cred 
        // Reference: https://github.com/nyxgeek/o365recon
        $string7 = /\.O365\.Users_LDAP_details\.txt/ nocase ascii wide
        // Description: script to retrieve information via O365 and AzureAD with a valid cred 
        // Reference: https://github.com/nyxgeek/o365recon
        $string8 = /\.O365\.Users_ProxyAddresses\.txt/ nocase ascii wide
        // Description: script to retrieve information via O365 and AzureAD with a valid cred 
        // Reference: https://github.com/nyxgeek/o365recon
        $string9 = /\/o365recon\.git/ nocase ascii wide
        // Description: script to retrieve information via O365 and AzureAD with a valid cred 
        // Reference: https://github.com/nyxgeek/o365recon
        $string10 = /\\.{0,1000}\.O365\.GroupMembership_AdminGroups\.txt/ nocase ascii wide
        // Description: script to retrieve information via O365 and AzureAD with a valid cred 
        // Reference: https://github.com/nyxgeek/o365recon
        $string11 = /\\.{0,1000}\.O365\.GroupMembership_VPNGroups\.txt/ nocase ascii wide
        // Description: script to retrieve information via O365 and AzureAD with a valid cred 
        // Reference: https://github.com/nyxgeek/o365recon
        $string12 = /\\.{0,1000}\.O365\.Roles_Admins\.txt/ nocase ascii wide
        // Description: script to retrieve information via O365 and AzureAD with a valid cred 
        // Reference: https://github.com/nyxgeek/o365recon
        $string13 = /49df12075c49bb956291cd11b2c53626174b4128309ada438d5d5e49265866f9/ nocase ascii wide
        // Description: script to retrieve information via O365 and AzureAD with a valid cred 
        // Reference: https://github.com/nyxgeek/o365recon
        $string14 = /JOB\sCOMPLETE\:\sGO\sGET\sYOUR\sLOOT\!/ nocase ascii wide
        // Description: script to retrieve information via O365 and AzureAD with a valid cred 
        // Reference: https://github.com/nyxgeek/o365recon
        $string15 = /nyxgeek\/o365recon/ nocase ascii wide
        // Description: script to retrieve information via O365 and AzureAD with a valid cred 
        // Reference: https://github.com/nyxgeek/o365recon
        $string16 = /o365recon\.ps1/ nocase ascii wide
        // Description: script to retrieve information via O365 and AzureAD with a valid cred 
        // Reference: https://github.com/nyxgeek/o365recon
        $string17 = /o365recon\-master/ nocase ascii wide

    condition:
        any of them
}
