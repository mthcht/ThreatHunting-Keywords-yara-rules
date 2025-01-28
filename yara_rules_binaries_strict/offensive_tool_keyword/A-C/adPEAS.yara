rule adPEAS
{
    meta:
        description = "Detection patterns for the tool 'adPEAS' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "adPEAS"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: adPEAS is a Powershell tool to automate Active Directory enumeration -  wrapper for PowerView - PoshADCS - BloodHound and others
        // Reference: https://github.com/61106960/adPEAS
        $string1 = /\sadPEAS\.ps1/ nocase ascii wide
        // Description: adPEAS is a Powershell tool to automate Active Directory enumeration -  wrapper for PowerView - PoshADCS - BloodHound and others
        // Reference: https://github.com/61106960/adPEAS
        $string2 = /\sadPEAS_DomainPolicy\.Sys/ nocase ascii wide
        // Description: adPEAS is a Powershell tool to automate Active Directory enumeration -  wrapper for PowerView - PoshADCS - BloodHound and others
        // Reference: https://github.com/61106960/adPEAS
        $string3 = /\sadPEAS_out\.txt/ nocase ascii wide
        // Description: adPEAS is a Powershell tool to automate Active Directory enumeration -  wrapper for PowerView - PoshADCS - BloodHound and others
        // Reference: https://github.com/61106960/adPEAS
        $string4 = /\sadPEAS\-Light\.ps1/ nocase ascii wide
        // Description: adPEAS is a Powershell tool to automate Active Directory enumeration -  wrapper for PowerView - PoshADCS - BloodHound and others
        // Reference: https://github.com/61106960/adPEAS
        $string5 = " -Module Bloodhound -Method All" nocase ascii wide
        // Description: adPEAS is a Powershell tool to automate Active Directory enumeration -  wrapper for PowerView - PoshADCS - BloodHound and others
        // Reference: https://github.com/61106960/adPEAS
        $string6 = " -Module Bloodhound -Scope All" nocase ascii wide
        // Description: adPEAS is a Powershell tool to automate Active Directory enumeration -  wrapper for PowerView - PoshADCS - BloodHound and others
        // Reference: https://github.com/61106960/adPEAS
        $string7 = /\$adPEAS_/ nocase ascii wide
        // Description: adPEAS is a Powershell tool to automate Active Directory enumeration -  wrapper for PowerView - PoshADCS - BloodHound and others
        // Reference: https://github.com/61106960/adPEAS
        $string8 = /\/adPEAS\.git/ nocase ascii wide
        // Description: adPEAS is a Powershell tool to automate Active Directory enumeration -  wrapper for PowerView - PoshADCS - BloodHound and others
        // Reference: https://github.com/61106960/adPEAS
        $string9 = /\/adPEAS\.ps1/ nocase ascii wide
        // Description: adPEAS is a Powershell tool to automate Active Directory enumeration -  wrapper for PowerView - PoshADCS - BloodHound and others
        // Reference: https://github.com/61106960/adPEAS
        $string10 = /\/adPEAS\-Light\.ps1/ nocase ascii wide
        // Description: adPEAS is a Powershell tool to automate Active Directory enumeration -  wrapper for PowerView - PoshADCS - BloodHound and others
        // Reference: https://github.com/61106960/adPEAS
        $string11 = /\\adPEAS\.ps1/ nocase ascii wide
        // Description: adPEAS is a Powershell tool to automate Active Directory enumeration -  wrapper for PowerView - PoshADCS - BloodHound and others
        // Reference: https://github.com/61106960/adPEAS
        $string12 = /\\adPEAS_DomainPolicy\.Sys/ nocase ascii wide
        // Description: adPEAS is a Powershell tool to automate Active Directory enumeration -  wrapper for PowerView - PoshADCS - BloodHound and others
        // Reference: https://github.com/61106960/adPEAS
        $string13 = /\\adPEAS_outputfile/ nocase ascii wide
        // Description: adPEAS is a Powershell tool to automate Active Directory enumeration -  wrapper for PowerView - PoshADCS - BloodHound and others
        // Reference: https://github.com/61106960/adPEAS
        $string14 = /\\adPEAS\-Light\.ps1/ nocase ascii wide
        // Description: adPEAS is a Powershell tool to automate Active Directory enumeration -  wrapper for PowerView - PoshADCS - BloodHound and others
        // Reference: https://github.com/61106960/adPEAS
        $string15 = /\\adPEAS\-main/ nocase ascii wide
        // Description: adPEAS is a Powershell tool to automate Active Directory enumeration -  wrapper for PowerView - PoshADCS - BloodHound and others
        // Reference: https://github.com/61106960/adPEAS
        $string16 = /\\adPEAS\-master/ nocase ascii wide
        // Description: adPEAS is a Powershell tool to automate Active Directory enumeration -  wrapper for PowerView - PoshADCS - BloodHound and others
        // Reference: https://github.com/61106960/adPEAS
        $string17 = "61106960/adPEAS" nocase ascii wide
        // Description: adPEAS is a Powershell tool to automate Active Directory enumeration -  wrapper for PowerView - PoshADCS - BloodHound and others
        // Reference: https://github.com/61106960/adPEAS
        $string18 = "6f919785361c350dd35b21573e02f681806645c50da3e98ddc703d2efa838dd6" nocase ascii wide
        // Description: adPEAS is a Powershell tool to automate Active Directory enumeration -  wrapper for PowerView - PoshADCS - BloodHound and others
        // Reference: https://github.com/61106960/adPEAS
        $string19 = "97f7f1ee8228a28173f07062e712dfaa25f64cfcf443a7f1d26c9502f6046b50" nocase ascii wide
        // Description: adPEAS is a Powershell tool to automate Active Directory enumeration -  wrapper for PowerView - PoshADCS - BloodHound and others
        // Reference: https://github.com/61106960/adPEAS
        $string20 = "Get-adPEASAccounts" nocase ascii wide
        // Description: adPEAS is a Powershell tool to automate Active Directory enumeration -  wrapper for PowerView - PoshADCS - BloodHound and others
        // Reference: https://github.com/61106960/adPEAS
        $string21 = "Get-adPEASADCS" nocase ascii wide
        // Description: adPEAS is a Powershell tool to automate Active Directory enumeration -  wrapper for PowerView - PoshADCS - BloodHound and others
        // Reference: https://github.com/61106960/adPEAS
        $string22 = "Get-adPEASBloodhound" nocase ascii wide
        // Description: adPEAS is a Powershell tool to automate Active Directory enumeration -  wrapper for PowerView - PoshADCS - BloodHound and others
        // Reference: https://github.com/61106960/adPEAS
        $string23 = "Get-adPEASComputer" nocase ascii wide
        // Description: adPEAS is a Powershell tool to automate Active Directory enumeration -  wrapper for PowerView - PoshADCS - BloodHound and others
        // Reference: https://github.com/61106960/adPEAS
        $string24 = "Get-adPEASCreds" nocase ascii wide
        // Description: adPEAS is a Powershell tool to automate Active Directory enumeration -  wrapper for PowerView - PoshADCS - BloodHound and others
        // Reference: https://github.com/61106960/adPEAS
        $string25 = "Get-adPEASDelegation" nocase ascii wide
        // Description: adPEAS is a Powershell tool to automate Active Directory enumeration -  wrapper for PowerView - PoshADCS - BloodHound and others
        // Reference: https://github.com/61106960/adPEAS
        $string26 = "Get-adPEASDomain" nocase ascii wide
        // Description: adPEAS is a Powershell tool to automate Active Directory enumeration -  wrapper for PowerView - PoshADCS - BloodHound and others
        // Reference: https://github.com/61106960/adPEAS
        $string27 = "Get-adPEASGPO" nocase ascii wide
        // Description: adPEAS is a Powershell tool to automate Active Directory enumeration -  wrapper for PowerView - PoshADCS - BloodHound and others
        // Reference: https://github.com/61106960/adPEAS
        $string28 = "Get-adPEASRights" nocase ascii wide
        // Description: adPEAS is a Powershell tool to automate Active Directory enumeration -  wrapper for PowerView - PoshADCS - BloodHound and others
        // Reference: https://github.com/61106960/adPEAS
        $string29 = "Get-WMIRegProxy" nocase ascii wide
        // Description: adPEAS is a Powershell tool to automate Active Directory enumeration -  wrapper for PowerView - PoshADCS - BloodHound and others
        // Reference: https://github.com/61106960/adPEAS
        $string30 = "Invoke-adPEAS" nocase ascii wide
        $metadata_regex_import = /\bimport\s+[a-zA-Z0-9_.]+\b/ nocase
        $metadata_regex_function = /function\s+[a-zA-Z_][a-zA-Z0-9_]*\(/ nocase ascii
        $metadata_regex_php = /<\?php/ nocase ascii
        $metadata_regex_createobject = /(CreateObject|WScript\.)/ nocase ascii
        $metadata_regex_script = /<script\b/ nocase ascii
        $metadata_regex_javascript = /(let\s|const\s|function\s|document\.|console\.)/ nocase ascii
        $metadata_regex_powershell = /(Write-Host|Get-[a-zA-Z]+|Invoke-|param\(|\.SYNOPSIS)/ nocase ascii
        $metadata_regex_batch = /@(echo\s|call\s|set\s|goto\s|if\s|for\s|rem\s)/ nocase ascii
        $metadata_regex_shebang = /^#!\// nocase ascii

    condition:
        ((filesize < 20MB and (
            uint16(0) == 0x5a4d or // Windows binary
            uint16(0) == 0x457f or // Linux ELF
            uint32be(0) == 0x7f454c46 or uint16(0) == 0xfeca or uint16(0) == 0xfacf or uint32(0) == 0xbebafeca or // macOS binary
            uint32(0) == 0x504B0304 or // Android APK, JAR
            uint32(0) == 0xCAFEBABE or // Java Class, Mach-O Universal Binary
            uint32(0) == 0x4D534346 or // Windows Cabinet File
            uint32(0) == 0xD0CF11E0 or // MSI Installer Package
            uint16(0) == 0x2321 or // Shebang (#!)
            uint16(0) == 0x3c3f // PHP and other script
        )) and 2 of ($string*)) or
        (filesize < 2MB and
        (
            2 of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}
