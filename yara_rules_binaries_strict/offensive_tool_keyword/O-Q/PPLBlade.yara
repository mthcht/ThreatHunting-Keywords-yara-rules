rule PPLBlade
{
    meta:
        description = "Detection patterns for the tool 'PPLBlade' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PPLBlade"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Protected Process Dumper Tool that support obfuscating memory dump and transferring it on remote workstations without dropping it onto the disk.
        // Reference: https://github.com/tastypepperoni/PPLBlade
        $string1 = /\s\-\-dumpmode\snetwork\s\-\-network\sraw\s\-\-ip\s.{0,100}\s\-\-port\s/ nocase ascii wide
        // Description: Protected Process Dumper Tool that support obfuscating memory dump and transferring it on remote workstations without dropping it onto the disk.
        // Reference: https://github.com/tastypepperoni/PPLBlade
        $string2 = " --dumpmode network --network smb " nocase ascii wide
        // Description: Protected Process Dumper Tool that support obfuscating memory dump and transferring it on remote workstations without dropping it onto the disk.
        // Reference: https://github.com/tastypepperoni/PPLBlade
        $string3 = /\s\-\-dumpname\slsass\.dmp/ nocase ascii wide
        // Description: Protected Process Dumper Tool that support obfuscating memory dump and transferring it on remote workstations without dropping it onto the disk.
        // Reference: https://github.com/tastypepperoni/PPLBlade
        $string4 = " --key PPLBlade" nocase ascii wide
        // Description: Protected Process Dumper Tool that support obfuscating memory dump and transferring it on remote workstations without dropping it onto the disk.
        // Reference: https://github.com/tastypepperoni/PPLBlade
        $string5 = /\s\-\-mode\sdecrypt\s\-\-dumpname\s.{0,100}\.dmp\s\-\-key\s/ nocase ascii wide
        // Description: Protected Process Dumper Tool that support obfuscating memory dump and transferring it on remote workstations without dropping it onto the disk.
        // Reference: https://github.com/tastypepperoni/PPLBlade
        $string6 = /\s\-\-mode\sdump\s\-\-name\s.{0,100}\.exe\s\-\-handle\sprocexp\s\-\-obfuscate/ nocase ascii wide
        // Description: Protected Process Dumper Tool that support obfuscating memory dump and transferring it on remote workstations without dropping it onto the disk.
        // Reference: https://github.com/tastypepperoni/PPLBlade
        $string7 = /\s\-\-mode\sdump\s\-\-name\slsass\.exe/ nocase ascii wide
        // Description: Protected Process Dumper Tool that support obfuscating memory dump and transferring it on remote workstations without dropping it onto the disk.
        // Reference: https://github.com/tastypepperoni/PPLBlade
        $string8 = /\/decrypted\.dmp/ nocase ascii wide
        // Description: Protected Process Dumper Tool that support obfuscating memory dump and transferring it on remote workstations without dropping it onto the disk.
        // Reference: https://github.com/tastypepperoni/PPLBlade
        $string9 = /\/PPLBlade\.git/ nocase ascii wide
        // Description: Protected Process Dumper Tool that support obfuscating memory dump and transferring it on remote workstations without dropping it onto the disk.
        // Reference: https://github.com/tastypepperoni/PPLBlade
        $string10 = /\[\+\]\sDeobfuscated\sdump\ssaved\sin\sfile\sdecrypted\.dmp/ nocase ascii wide
        // Description: Protected Process Dumper Tool that support obfuscating memory dump and transferring it on remote workstations without dropping it onto the disk.
        // Reference: https://github.com/tastypepperoni/PPLBlade
        $string11 = /\\decrypted\.dmp/ nocase ascii wide
        // Description: Protected Process Dumper Tool that support obfuscating memory dump and transferring it on remote workstations without dropping it onto the disk.
        // Reference: https://github.com/tastypepperoni/PPLBlade
        $string12 = /\\PPLBlade\-main/ nocase ascii wide
        // Description: Protected Process Dumper Tool that support obfuscating memory dump and transferring it on remote workstations without dropping it onto the disk.
        // Reference: https://github.com/tastypepperoni/PPLBlade
        $string13 = "dothatlsassthing" nocase ascii wide
        // Description: Protected Process Dumper Tool that support obfuscating memory dump and transferring it on remote workstations without dropping it onto the disk.
        // Reference: https://github.com/tastypepperoni/PPLBlade
        $string14 = /PPLBlade\.dmp/ nocase ascii wide
        // Description: Protected Process Dumper Tool that support obfuscating memory dump and transferring it on remote workstations without dropping it onto the disk.
        // Reference: https://github.com/tastypepperoni/PPLBlade
        $string15 = /PPLBlade\.exe/ nocase ascii wide
        // Description: Protected Process Dumper Tool that support obfuscating memory dump and transferring it on remote workstations without dropping it onto the disk.
        // Reference: https://github.com/tastypepperoni/PPLBlade
        $string16 = /PPLBlade\-main\./ nocase ascii wide
        // Description: Protected Process Dumper Tool that support obfuscating memory dump and transferring it on remote workstations without dropping it onto the disk.
        // Reference: https://github.com/tastypepperoni/PPLBlade
        $string17 = "tastypepperoni/PPLBlade" nocase ascii wide
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
        )) and any of ($string*)) or
        (filesize < 2MB and
        (
            any of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}
