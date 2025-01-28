rule PoshADCS
{
    meta:
        description = "Detection patterns for the tool 'PoshADCS' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PoshADCS"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: attack vectors against Active Directory by abusing Active Directory Certificate Services (ADCS)
        // Reference: https://github.com/cfalta/PoshADCS
        $string1 = /\sADCS\.ps1/ nocase ascii wide
        // Description: attack vectors against Active Directory by abusing Active Directory Certificate Services (ADCS)
        // Reference: https://github.com/cfalta/PoshADCS
        $string2 = /\/ADCS\.ps1/ nocase ascii wide
        // Description: attack vectors against Active Directory by abusing Active Directory Certificate Services (ADCS)
        // Reference: https://github.com/cfalta/PoshADCS
        $string3 = /\/PoshADCS\.git/ nocase ascii wide
        // Description: attack vectors against Active Directory by abusing Active Directory Certificate Services (ADCS)
        // Reference: https://github.com/cfalta/PoshADCS
        $string4 = /\\ADCS\.ps1/ nocase ascii wide
        // Description: attack vectors against Active Directory by abusing Active Directory Certificate Services (ADCS)
        // Reference: https://github.com/cfalta/PoshADCS
        $string5 = /\\PoshADCS\-master/ nocase ascii wide
        // Description: attack vectors against Active Directory by abusing Active Directory Certificate Services (ADCS)
        // Reference: https://github.com/cfalta/PoshADCS
        $string6 = "156a20924b696b89e6df463edce6afe72bc8348af0c52c399ff5d88e3a9d6e5a" nocase ascii wide
        // Description: attack vectors against Active Directory by abusing Active Directory Certificate Services (ADCS)
        // Reference: https://github.com/cfalta/PoshADCS
        $string7 = "cfalta/PoshADCS" nocase ascii wide
        // Description: attack vectors against Active Directory by abusing Active Directory Certificate Services (ADCS)
        // Reference: https://github.com/cfalta/PoshADCS
        $string8 = "Convert-ADCSFlag " nocase ascii wide
        // Description: attack vectors against Active Directory by abusing Active Directory Certificate Services (ADCS)
        // Reference: https://github.com/cfalta/PoshADCS
        $string9 = "Convert-ADCSPrivateKeyFlag" nocase ascii wide
        // Description: attack vectors against Active Directory by abusing Active Directory Certificate Services (ADCS)
        // Reference: https://github.com/cfalta/PoshADCS
        $string10 = "Get-ADCSTemplateACL" nocase ascii wide
        // Description: attack vectors against Active Directory by abusing Active Directory Certificate Services (ADCS)
        // Reference: https://github.com/cfalta/PoshADCS
        $string11 = /PoshADCS\-master\.zip/ nocase ascii wide

    condition:
        any of them
}
