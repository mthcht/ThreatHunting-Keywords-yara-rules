rule MicroBurst
{
    meta:
        description = "Detection patterns for the tool 'MicroBurst' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "MicroBurst"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A collection of scripts for assessing Microsoft Azure security
        // Reference: https://github.com/NetSPI/MicroBurst
        $string1 = /\/MicroBurst\.git/ nocase ascii wide
        // Description: A collection of scripts for assessing Microsoft Azure security
        // Reference: https://github.com/NetSPI/MicroBurst
        $string2 = /\\Files\\ContainersFileUrls\.txt/ nocase ascii wide
        // Description: A collection of scripts for assessing Microsoft Azure security
        // Reference: https://github.com/NetSPI/MicroBurst
        $string3 = /\\MSOL\\DomainCompanyInfo\.txt/ nocase ascii wide
        // Description: A collection of scripts for assessing Microsoft Azure security
        // Reference: https://github.com/NetSPI/MicroBurst
        $string4 = /\\Resources\\Disks\-NoEncryption\.txt/ nocase ascii wide
        // Description: A collection of scripts for assessing Microsoft Azure security
        // Reference: https://github.com/NetSPI/MicroBurst
        $string5 = /C\:\\dsc_hello\.txt/ nocase ascii wide
        // Description: A collection of scripts for assessing Microsoft Azure security
        // Reference: https://github.com/NetSPI/MicroBurst
        $string6 = /Get\-AzAutomationAccountCredsREST\.ps1/ nocase ascii wide
        // Description: A collection of scripts for assessing Microsoft Azure security
        // Reference: https://github.com/NetSPI/MicroBurst
        $string7 = /Get\-AzDomainInfo/ nocase ascii wide
        // Description: A collection of scripts for assessing Microsoft Azure security
        // Reference: https://github.com/NetSPI/MicroBurst
        $string8 = /Get\-AzDomainInfoREST\.ps1/ nocase ascii wide
        // Description: A collection of scripts for assessing Microsoft Azure security
        // Reference: https://github.com/NetSPI/MicroBurst
        $string9 = /Get\-AzKeyVaultKeysREST\.ps1/ nocase ascii wide
        // Description: A collection of scripts for assessing Microsoft Azure security
        // Reference: https://github.com/NetSPI/MicroBurst
        $string10 = /Get\-AzKeyVaultSecretsREST\.ps1/ nocase ascii wide
        // Description: A collection of scripts for assessing Microsoft Azure security
        // Reference: https://github.com/NetSPI/MicroBurst
        $string11 = /Get\-AzPasswords/ nocase ascii wide
        // Description: A collection of scripts for assessing Microsoft Azure security
        // Reference: https://github.com/NetSPI/MicroBurst
        $string12 = /Get\-AZStorageKeysREST\.ps1/ nocase ascii wide
        // Description: A collection of scripts for assessing Microsoft Azure security
        // Reference: https://github.com/NetSPI/MicroBurst
        $string13 = /Get\-AzureADDomainInfo/ nocase ascii wide
        // Description: A collection of scripts for assessing Microsoft Azure security
        // Reference: https://github.com/NetSPI/MicroBurst
        $string14 = /Get\-AzureADDomainInfo\.ps1/ nocase ascii wide
        // Description: A collection of scripts for assessing Microsoft Azure security
        // Reference: https://github.com/NetSPI/MicroBurst
        $string15 = /Get\-AzurePasswords/ nocase ascii wide
        // Description: A collection of scripts for assessing Microsoft Azure security
        // Reference: https://github.com/NetSPI/MicroBurst
        $string16 = /Get\-AzUserAssignedIdentity/ nocase ascii wide
        // Description: A collection of scripts for assessing Microsoft Azure security
        // Reference: https://github.com/NetSPI/MicroBurst
        $string17 = /Invoke\-APIConnectionHijack\.ps1/ nocase ascii wide
        // Description: A collection of scripts for assessing Microsoft Azure security
        // Reference: https://github.com/NetSPI/MicroBurst
        $string18 = /Invoke\-AzElevatedAccessToggle/ nocase ascii wide
        // Description: A collection of scripts for assessing Microsoft Azure security
        // Reference: https://github.com/NetSPI/MicroBurst
        $string19 = /Invoke\-AzRESTBastionShareableLink/ nocase ascii wide
        // Description: A collection of scripts for assessing Microsoft Azure security
        // Reference: https://github.com/NetSPI/MicroBurst
        $string20 = /Invoke\-AzureRmVMBulkCMD\.ps1/ nocase ascii wide
        // Description: A collection of scripts for assessing Microsoft Azure security
        // Reference: https://github.com/NetSPI/MicroBurst
        $string21 = /Invoke\-AzVMBulkCMD\.ps1/ nocase ascii wide
        // Description: A collection of scripts for assessing Microsoft Azure security
        // Reference: https://github.com/NetSPI/MicroBurst
        $string22 = /Invoke\-EnumerateAzureBlobs\.ps1/ nocase ascii wide
        // Description: A collection of scripts for assessing Microsoft Azure security
        // Reference: https://github.com/NetSPI/MicroBurst
        $string23 = /Invoke\-EnumerateAzureSubDomains\.ps1/ nocase ascii wide
        // Description: A collection of scripts for assessing Microsoft Azure security
        // Reference: https://github.com/NetSPI/MicroBurst
        $string24 = /MicroBurst\.psm1/ nocase ascii wide
        // Description: A collection of scripts for assessing Microsoft Azure security
        // Reference: https://github.com/NetSPI/MicroBurst
        $string25 = /MicroBurst\-Az\.psm1/ nocase ascii wide
        // Description: A collection of scripts for assessing Microsoft Azure security
        // Reference: https://github.com/NetSPI/MicroBurst
        $string26 = /MicroBurst\-AzureAD/ nocase ascii wide
        // Description: A collection of scripts for assessing Microsoft Azure security
        // Reference: https://github.com/NetSPI/MicroBurst
        $string27 = /MicroBurst\-AzureREST/ nocase ascii wide
        // Description: A collection of scripts for assessing Microsoft Azure security
        // Reference: https://github.com/NetSPI/MicroBurst
        $string28 = /MicroBurst\-AzureRM/ nocase ascii wide
        // Description: A collection of scripts for assessing Microsoft Azure security
        // Reference: https://github.com/NetSPI/MicroBurst
        $string29 = /MicroBurst\-master/ nocase ascii wide
        // Description: A collection of scripts for assessing Microsoft Azure security
        // Reference: https://github.com/NetSPI/MicroBurst
        $string30 = /MicroBurst\-Misc\.psm1/ nocase ascii wide
        // Description: A collection of scripts for assessing Microsoft Azure security
        // Reference: https://github.com/NetSPI/MicroBurst
        $string31 = /MicroBurst\-MSOL/ nocase ascii wide
        // Description: A collection of scripts for assessing Microsoft Azure security
        // Reference: https://github.com/NetSPI/MicroBurst
        $string32 = /OwnerPersist\-POST\./ nocase ascii wide

    condition:
        any of them
}
