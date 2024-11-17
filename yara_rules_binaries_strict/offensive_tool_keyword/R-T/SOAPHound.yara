rule SOAPHound
{
    meta:
        description = "Detection patterns for the tool 'SOAPHound' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SOAPHound"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: enumerate Active Directory environments via the Active Directory Web Services (ADWS)
        // Reference: https://github.com/FalconForceTeam/SOAPHound
        $string1 = /\s\-\-bhdump\s/ nocase ascii wide
        // Description: enumerate Active Directory environments via the Active Directory Web Services (ADWS)
        // Reference: https://github.com/FalconForceTeam/SOAPHound
        $string2 = /\s\-\-certdump\s/ nocase ascii wide
        // Description: enumerate Active Directory environments via the Active Directory Web Services (ADWS)
        // Reference: https://github.com/FalconForceTeam/SOAPHound
        $string3 = /\s\-\-dnsdump\s/ nocase ascii wide
        // Description: enumerate Active Directory environments via the Active Directory Web Services (ADWS)
        // Reference: https://github.com/FalconForceTeam/SOAPHound
        $string4 = /\sSOAPHound\.ADWS/ nocase ascii wide
        // Description: enumerate Active Directory environments via the Active Directory Web Services (ADWS)
        // Reference: https://github.com/FalconForceTeam/SOAPHound
        $string5 = /\\"ADWS\srequest\swith\sldapbase\s\(/ nocase ascii wide
        // Description: enumerate Active Directory environments via the Active Directory Web Services (ADWS)
        // Reference: https://github.com/FalconForceTeam/SOAPHound
        $string6 = /\\"Dump\sBH\sdata\\"/ nocase ascii wide
        // Description: enumerate Active Directory environments via the Active Directory Web Services (ADWS)
        // Reference: https://github.com/FalconForceTeam/SOAPHound
        $string7 = /\.exe\s\s\-\-buildcache\s\-c\s.{0,100}\\cache\.txt/ nocase ascii wide
        // Description: enumerate Active Directory environments via the Active Directory Web Services (ADWS)
        // Reference: https://github.com/FalconForceTeam/SOAPHound
        $string8 = /\.exe\s\-\-showstats\s\-c\s.{0,100}\\cache\.txt/ nocase ascii wide
        // Description: enumerate Active Directory environments via the Active Directory Web Services (ADWS)
        // Reference: https://github.com/FalconForceTeam/SOAPHound
        $string9 = /\/SOAPHound\.exe/ nocase ascii wide
        // Description: enumerate Active Directory environments via the Active Directory Web Services (ADWS)
        // Reference: https://github.com/FalconForceTeam/SOAPHound
        $string10 = /\/SOAPHound\.git/ nocase ascii wide
        // Description: enumerate Active Directory environments via the Active Directory Web Services (ADWS)
        // Reference: https://github.com/FalconForceTeam/SOAPHound
        $string11 = /\/SOAPHound\/Program\.cs/ nocase ascii wide
        // Description: enumerate Active Directory environments via the Active Directory Web Services (ADWS)
        // Reference: https://github.com/FalconForceTeam/SOAPHound
        $string12 = /\\SOAPHound\.csproj/ nocase ascii wide
        // Description: enumerate Active Directory environments via the Active Directory Web Services (ADWS)
        // Reference: https://github.com/FalconForceTeam/SOAPHound
        $string13 = /\\SOAPHound\.exe/ nocase ascii wide
        // Description: enumerate Active Directory environments via the Active Directory Web Services (ADWS)
        // Reference: https://github.com/FalconForceTeam/SOAPHound
        $string14 = /\\SOAPHound\.sln/ nocase ascii wide
        // Description: enumerate Active Directory environments via the Active Directory Web Services (ADWS)
        // Reference: https://github.com/FalconForceTeam/SOAPHound
        $string15 = /\\SOAPHound\\Enums\\/ nocase ascii wide
        // Description: enumerate Active Directory environments via the Active Directory Web Services (ADWS)
        // Reference: https://github.com/FalconForceTeam/SOAPHound
        $string16 = /\\SOAPHound\\Program\.cs/ nocase ascii wide
        // Description: enumerate Active Directory environments via the Active Directory Web Services (ADWS)
        // Reference: https://github.com/FalconForceTeam/SOAPHound
        $string17 = /\\SOAPHound\-master/ nocase ascii wide
        // Description: enumerate Active Directory environments via the Active Directory Web Services (ADWS)
        // Reference: https://github.com/FalconForceTeam/SOAPHound
        $string18 = /33571B09\-4E94\-43CB\-ABDC\-0226D769E701/ nocase ascii wide
        // Description: enumerate Active Directory environments via the Active Directory Web Services (ADWS)
        // Reference: https://github.com/FalconForceTeam/SOAPHound
        $string19 = /Domain\scontroller\sis\smissing.{0,100}\suse\s\-\-dc\./ nocase ascii wide
        // Description: enumerate Active Directory environments via the Active Directory Web Services (ADWS)
        // Reference: https://github.com/FalconForceTeam/SOAPHound
        $string20 = /Dump\sAD\sCertificate\sServices\sdata/ nocase ascii wide
        // Description: enumerate Active Directory environments via the Active Directory Web Services (ADWS)
        // Reference: https://github.com/FalconForceTeam/SOAPHound
        $string21 = /Dump\sAD\sIntegrated\sDNS\sdata/ nocase ascii wide
        // Description: enumerate Active Directory environments via the Active Directory Web Services (ADWS)
        // Reference: https://github.com/FalconForceTeam/SOAPHound
        $string22 = /FalconForceTeam\/SOAPHound/ nocase ascii wide
        // Description: enumerate Active Directory environments via the Active Directory Web Services (ADWS)
        // Reference: https://github.com/FalconForceTeam/SOAPHound
        $string23 = /Password\sto\suse\sfor\sADWS\sConnection/ nocase ascii wide
        // Description: enumerate Active Directory environments via the Active Directory Web Services (ADWS)
        // Reference: https://github.com/FalconForceTeam/SOAPHound
        $string24 = /SOAPHound\sPoC\s1\.0\.1\-beta/ nocase ascii wide
        // Description: enumerate Active Directory environments via the Active Directory Web Services (ADWS)
        // Reference: https://github.com/FalconForceTeam/SOAPHound
        $string25 = /SOAPHound\.exe\s/ nocase ascii wide
        // Description: enumerate Active Directory environments via the Active Directory Web Services (ADWS)
        // Reference: https://github.com/FalconForceTeam/SOAPHound
        $string26 = /SOAPHound\.Processors/ nocase ascii wide
        // Description: enumerate Active Directory environments via the Active Directory Web Services (ADWS)
        // Reference: https://github.com/FalconForceTeam/SOAPHound
        $string27 = /Specify\sdomain\sfor\senumeration/ nocase ascii wide
        // Description: enumerate Active Directory environments via the Active Directory Web Services (ADWS)
        // Reference: https://github.com/FalconForceTeam/SOAPHound
        $string28 = /Username\sto\suse\sfor\sADWS\sConnection\.\sFormat\:\sdomain\\\\user\sor\suser\@domain/ nocase ascii wide
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
