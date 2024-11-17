rule AmsiBypass
{
    meta:
        description = "Detection patterns for the tool 'AmsiBypass' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "AmsiBypass"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: bypassing Anti-Malware Scanning Interface (AMSI) features
        // Reference: https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell
        $string1 = /\/AmsiBypass\./ nocase ascii wide
        // Description: bypassing Anti-Malware Scanning Interface (AMSI) features
        // Reference: https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell
        $string2 = /\/Amsi\-Bypass\-Powershell\.git/ nocase ascii wide
        // Description: bypassing Anti-Malware Scanning Interface (AMSI) features
        // Reference: https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell
        $string3 = /\/opt\/Projects\/AmsiBypass\// nocase ascii wide
        // Description: bypassing Anti-Malware Scanning Interface (AMSI) features
        // Reference: https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell
        $string4 = /\\AmsiBypass\./ nocase ascii wide
        // Description: bypassing Anti-Malware Scanning Interface (AMSI) features
        // Reference: https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell
        $string5 = /132ab5d9aa388ae3a6575a01fadeb7fa7f77aac1150fc54bc1d20ae32b58ddc5/ nocase ascii wide
        // Description: bypassing Anti-Malware Scanning Interface (AMSI) features
        // Reference: https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell
        $string6 = /Invoke\-PsUACme\s\-Method\s/ nocase ascii wide
        // Description: bypassing Anti-Malware Scanning Interface (AMSI) features
        // Reference: https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell
        $string7 = /Modified\-Amsi\-ScanBuffer\-Patch/ nocase ascii wide
        // Description: bypassing Anti-Malware Scanning Interface (AMSI) features
        // Reference: https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell
        $string8 = /Nishang\-all\-in\-one/ nocase ascii wide
        // Description: bypassing Anti-Malware Scanning Interface (AMSI) features
        // Reference: https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell
        $string9 = /Patching\-AMSI\-AmsiScanBuffer\-by\-rasta\-mouse/ nocase ascii wide
        // Description: bypassing Anti-Malware Scanning Interface (AMSI) features
        // Reference: https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell
        $string10 = /S3cur3Th1sSh1t\/Amsi\-Bypass\-Powershell/ nocase ascii wide
        // Description: bypassing Anti-Malware Scanning Interface (AMSI) features
        // Reference: https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell
        $string11 = /\'System\.Ma\'\+\'nag\'\+\'eme\'\+\'nt\.Autom\'\+\'ation\.A\'\+\'ms\'\+\'iU\'\+\'ti\'\+\'ls\'/ nocase ascii wide
        // Description: bypassing Anti-Malware Scanning Interface (AMSI) features
        // Reference: https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell
        $string12 = /Tztufn\/Nbobhfnfou\/Bvupnbujpo\/BntjVujmt/ nocase ascii wide
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
