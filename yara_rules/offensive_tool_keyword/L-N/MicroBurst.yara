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
        $string1 = /.{0,1000}\/MicroBurst\.git.{0,1000}/ nocase ascii wide
        // Description: A collection of scripts for assessing Microsoft Azure security
        // Reference: https://github.com/NetSPI/MicroBurst
        $string2 = /.{0,1000}\\Files\\ContainersFileUrls\.txt.{0,1000}/ nocase ascii wide
        // Description: A collection of scripts for assessing Microsoft Azure security
        // Reference: https://github.com/NetSPI/MicroBurst
        $string3 = /.{0,1000}\\MSOL\\DomainCompanyInfo\.txt.{0,1000}/ nocase ascii wide
        // Description: A collection of scripts for assessing Microsoft Azure security
        // Reference: https://github.com/NetSPI/MicroBurst
        $string4 = /.{0,1000}\\Resources\\Disks\-NoEncryption\.txt.{0,1000}/ nocase ascii wide
        // Description: A collection of scripts for assessing Microsoft Azure security
        // Reference: https://github.com/NetSPI/MicroBurst
        $string5 = /.{0,1000}C:\\dsc_hello\.txt.{0,1000}/ nocase ascii wide
        // Description: A collection of scripts for assessing Microsoft Azure security
        // Reference: https://github.com/NetSPI/MicroBurst
        $string6 = /.{0,1000}Get\-AzAutomationAccountCredsREST\.ps1.{0,1000}/ nocase ascii wide
        // Description: A collection of scripts for assessing Microsoft Azure security
        // Reference: https://github.com/NetSPI/MicroBurst
        $string7 = /.{0,1000}Get\-AzDomainInfo.{0,1000}/ nocase ascii wide
        // Description: A collection of scripts for assessing Microsoft Azure security
        // Reference: https://github.com/NetSPI/MicroBurst
        $string8 = /.{0,1000}Get\-AzDomainInfoREST\.ps1.{0,1000}/ nocase ascii wide
        // Description: A collection of scripts for assessing Microsoft Azure security
        // Reference: https://github.com/NetSPI/MicroBurst
        $string9 = /.{0,1000}Get\-AzKeyVaultKeysREST\.ps1.{0,1000}/ nocase ascii wide
        // Description: A collection of scripts for assessing Microsoft Azure security
        // Reference: https://github.com/NetSPI/MicroBurst
        $string10 = /.{0,1000}Get\-AzKeyVaultSecretsREST\.ps1.{0,1000}/ nocase ascii wide
        // Description: A collection of scripts for assessing Microsoft Azure security
        // Reference: https://github.com/NetSPI/MicroBurst
        $string11 = /.{0,1000}Get\-AzPasswords.{0,1000}/ nocase ascii wide
        // Description: A collection of scripts for assessing Microsoft Azure security
        // Reference: https://github.com/NetSPI/MicroBurst
        $string12 = /.{0,1000}Get\-AZStorageKeysREST\.ps1.{0,1000}/ nocase ascii wide
        // Description: A collection of scripts for assessing Microsoft Azure security
        // Reference: https://github.com/NetSPI/MicroBurst
        $string13 = /.{0,1000}Get\-AzureADDomainInfo.{0,1000}/ nocase ascii wide
        // Description: A collection of scripts for assessing Microsoft Azure security
        // Reference: https://github.com/NetSPI/MicroBurst
        $string14 = /.{0,1000}Get\-AzureADDomainInfo\.ps1.{0,1000}/ nocase ascii wide
        // Description: A collection of scripts for assessing Microsoft Azure security
        // Reference: https://github.com/NetSPI/MicroBurst
        $string15 = /.{0,1000}Get\-AzurePasswords.{0,1000}/ nocase ascii wide
        // Description: A collection of scripts for assessing Microsoft Azure security
        // Reference: https://github.com/NetSPI/MicroBurst
        $string16 = /.{0,1000}Get\-AzUserAssignedIdentity.{0,1000}/ nocase ascii wide
        // Description: A collection of scripts for assessing Microsoft Azure security
        // Reference: https://github.com/NetSPI/MicroBurst
        $string17 = /.{0,1000}Invoke\-APIConnectionHijack\.ps1.{0,1000}/ nocase ascii wide
        // Description: A collection of scripts for assessing Microsoft Azure security
        // Reference: https://github.com/NetSPI/MicroBurst
        $string18 = /.{0,1000}Invoke\-AzElevatedAccessToggle.{0,1000}/ nocase ascii wide
        // Description: A collection of scripts for assessing Microsoft Azure security
        // Reference: https://github.com/NetSPI/MicroBurst
        $string19 = /.{0,1000}Invoke\-AzRESTBastionShareableLink.{0,1000}/ nocase ascii wide
        // Description: A collection of scripts for assessing Microsoft Azure security
        // Reference: https://github.com/NetSPI/MicroBurst
        $string20 = /.{0,1000}Invoke\-AzureRmVMBulkCMD\.ps1.{0,1000}/ nocase ascii wide
        // Description: A collection of scripts for assessing Microsoft Azure security
        // Reference: https://github.com/NetSPI/MicroBurst
        $string21 = /.{0,1000}Invoke\-AzVMBulkCMD\.ps1.{0,1000}/ nocase ascii wide
        // Description: A collection of scripts for assessing Microsoft Azure security
        // Reference: https://github.com/NetSPI/MicroBurst
        $string22 = /.{0,1000}Invoke\-EnumerateAzureBlobs\.ps1.{0,1000}/ nocase ascii wide
        // Description: A collection of scripts for assessing Microsoft Azure security
        // Reference: https://github.com/NetSPI/MicroBurst
        $string23 = /.{0,1000}Invoke\-EnumerateAzureSubDomains\.ps1.{0,1000}/ nocase ascii wide
        // Description: A collection of scripts for assessing Microsoft Azure security
        // Reference: https://github.com/NetSPI/MicroBurst
        $string24 = /.{0,1000}MicroBurst\.psm1.{0,1000}/ nocase ascii wide
        // Description: A collection of scripts for assessing Microsoft Azure security
        // Reference: https://github.com/NetSPI/MicroBurst
        $string25 = /.{0,1000}MicroBurst\-Az\.psm1.{0,1000}/ nocase ascii wide
        // Description: A collection of scripts for assessing Microsoft Azure security
        // Reference: https://github.com/NetSPI/MicroBurst
        $string26 = /.{0,1000}MicroBurst\-AzureAD.{0,1000}/ nocase ascii wide
        // Description: A collection of scripts for assessing Microsoft Azure security
        // Reference: https://github.com/NetSPI/MicroBurst
        $string27 = /.{0,1000}MicroBurst\-AzureREST.{0,1000}/ nocase ascii wide
        // Description: A collection of scripts for assessing Microsoft Azure security
        // Reference: https://github.com/NetSPI/MicroBurst
        $string28 = /.{0,1000}MicroBurst\-AzureRM.{0,1000}/ nocase ascii wide
        // Description: A collection of scripts for assessing Microsoft Azure security
        // Reference: https://github.com/NetSPI/MicroBurst
        $string29 = /.{0,1000}MicroBurst\-master.{0,1000}/ nocase ascii wide
        // Description: A collection of scripts for assessing Microsoft Azure security
        // Reference: https://github.com/NetSPI/MicroBurst
        $string30 = /.{0,1000}MicroBurst\-Misc\.psm1.{0,1000}/ nocase ascii wide
        // Description: A collection of scripts for assessing Microsoft Azure security
        // Reference: https://github.com/NetSPI/MicroBurst
        $string31 = /.{0,1000}MicroBurst\-MSOL.{0,1000}/ nocase ascii wide
        // Description: A collection of scripts for assessing Microsoft Azure security
        // Reference: https://github.com/NetSPI/MicroBurst
        $string32 = /.{0,1000}OwnerPersist\-POST\..{0,1000}/ nocase ascii wide

    condition:
        any of them
}
