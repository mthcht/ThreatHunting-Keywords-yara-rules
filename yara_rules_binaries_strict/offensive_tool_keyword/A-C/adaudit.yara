rule adaudit
{
    meta:
        description = "Detection patterns for the tool 'adaudit' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "adaudit"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Powershell script to do domain auditing automation
        // Reference: https://github.com/phillips321/adaudit
        $string1 = /\sADAudit\.ps1/ nocase ascii wide
        // Description: Powershell script to do domain auditing automation
        // Reference: https://github.com/phillips321/adaudit
        $string2 = /\/adaudit\.git/ nocase ascii wide
        // Description: Powershell script to do domain auditing automation
        // Reference: https://github.com/phillips321/adaudit
        $string3 = /\/ADAudit\.ps1/ nocase ascii wide
        // Description: Powershell script to do domain auditing automation
        // Reference: https://github.com/phillips321/adaudit
        $string4 = /\[\!\]\sYou\shave\sDCs\swith\sRC4\sor\sDES\sallowed\sfor\sKerberos\!\!\!/ nocase ascii wide
        // Description: Powershell script to do domain auditing automation
        // Reference: https://github.com/phillips321/adaudit
        $string5 = /\\accounts_passdontexpire\.txt/ nocase ascii wide
        // Description: Powershell script to do domain auditing automation
        // Reference: https://github.com/phillips321/adaudit
        $string6 = /\\ADAudit\.ps1/ nocase ascii wide
        // Description: Powershell script to do domain auditing automation
        // Reference: https://github.com/phillips321/adaudit
        $string7 = /\\dangerousACL_Computer\.txt/ nocase ascii wide
        // Description: Powershell script to do domain auditing automation
        // Reference: https://github.com/phillips321/adaudit
        $string8 = /\\dangerousACL_Groups\.txt/ nocase ascii wide
        // Description: Powershell script to do domain auditing automation
        // Reference: https://github.com/phillips321/adaudit
        $string9 = /\\dcs_weak_kerberos_ciphersuite\.txt/ nocase ascii wide
        // Description: Powershell script to do domain auditing automation
        // Reference: https://github.com/phillips321/adaudit
        $string10 = /\\domain_admins\.txt/ nocase ascii wide
        // Description: Powershell script to do domain auditing automation
        // Reference: https://github.com/phillips321/adaudit
        $string11 = /\\enterprise_admins\.txt/ nocase ascii wide
        // Description: Powershell script to do domain auditing automation
        // Reference: https://github.com/phillips321/adaudit
        $string12 = /\]\sCheck\sfor\sADCS\sVulnerabilities/ nocase ascii wide
        // Description: Powershell script to do domain auditing automation
        // Reference: https://github.com/phillips321/adaudit
        $string13 = /5f871566a9113e31357e084743f12b74b7199019e66cd10847b61b5666ecf9b1/ nocase ascii wide
        // Description: Powershell script to do domain auditing automation
        // Reference: https://github.com/phillips321/adaudit
        $string14 = /Find\-DangerousACLPermissions/ nocase ascii wide
        // Description: Powershell script to do domain auditing automation
        // Reference: https://github.com/phillips321/adaudit
        $string15 = /Get\-AccountPassDontExpire/ nocase ascii wide
        // Description: Powershell script to do domain auditing automation
        // Reference: https://github.com/phillips321/adaudit
        $string16 = /Get\-ADCSVulns/ nocase ascii wide
        // Description: Powershell script to do domain auditing automation
        // Reference: https://github.com/phillips321/adaudit
        $string17 = /Get\-ADUsersWithoutPreAuth/ nocase ascii wide
        // Description: Powershell script to do domain auditing automation
        // Reference: https://github.com/phillips321/adaudit
        $string18 = /Get\-DCsNotOwnedByDA/ nocase ascii wide
        // Description: Powershell script to do domain auditing automation
        // Reference: https://github.com/phillips321/adaudit
        $string19 = /Get\-GPOEnum/ nocase ascii wide
        // Description: Powershell script to do domain auditing automation
        // Reference: https://github.com/phillips321/adaudit
        $string20 = /Get\-GPOsPerOU/ nocase ascii wide
        // Description: Powershell script to do domain auditing automation
        // Reference: https://github.com/phillips321/adaudit
        $string21 = /Get\-GPOtoFile/ nocase ascii wide
        // Description: Powershell script to do domain auditing automation
        // Reference: https://github.com/phillips321/adaudit
        $string22 = /Get\-GPPPassword\./ nocase ascii wide
        // Description: Powershell script to do domain auditing automation
        // Reference: https://github.com/phillips321/adaudit
        $string23 = /Get\-NTDSdit/ nocase ascii wide
        // Description: Powershell script to do domain auditing automation
        // Reference: https://github.com/phillips321/adaudit
        $string24 = /Get\-PrivilegedGroupAccounts/ nocase ascii wide
        // Description: Powershell script to do domain auditing automation
        // Reference: https://github.com/phillips321/adaudit
        $string25 = /Get\-PrivilegedGroupMembership/ nocase ascii wide
        // Description: Powershell script to do domain auditing automation
        // Reference: https://github.com/phillips321/adaudit
        $string26 = /Kerberoast\sAttack\s\-\sServices\sConfigured\sWith\sa\sWeak\sPassword/ nocase ascii wide
        // Description: Powershell script to do domain auditing automation
        // Reference: https://github.com/phillips321/adaudit
        $string27 = /phillips321\/adaudit/ nocase ascii wide
        // Description: Powershell script to do domain auditing automation
        // Reference: https://github.com/phillips321/adaudit
        $string28 = /Write\-Nessus\-Finding/ nocase ascii wide
        // Description: Powershell script to do domain auditing automation
        // Reference: https://github.com/phillips321/adaudit
        $string29 = /Write\-Nessus\-Footer/ nocase ascii wide
        // Description: Powershell script to do domain auditing automation
        // Reference: https://github.com/phillips321/adaudit
        $string30 = /Write\-Nessus\-Header/ nocase ascii wide
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
