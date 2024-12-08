rule Dumpert
{
    meta:
        description = "Detection patterns for the tool 'Dumpert' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Dumpert"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Dumpert. an LSASS memory dumper using direct system calls and API unhooking Recent malware research shows that there is an increase in malware that is using direct system calls to evade user-mode API hooks used by security products. This tool demonstrates the use of direct System Calls and API unhooking and combine these techniques in a proof of concept code which can be used to create a LSASS memory dump using Cobalt Strike. while not touching disk and evading AV/EDR monitored user-mode API calls.
        // Reference: https://github.com/outflanknl/Dumpert
        $string1 = /\[\+\]\sDump\s\%wZ\smemory\sto\:\s\%wZ/ nocase ascii wide
        // Description: Dumpert. an LSASS memory dumper using direct system calls and API unhooking Recent malware research shows that there is an increase in malware that is using direct system calls to evade user-mode API hooks used by security products. This tool demonstrates the use of direct System Calls and API unhooking and combine these techniques in a proof of concept code which can be used to create a LSASS memory dump using Cobalt Strike. while not touching disk and evading AV/EDR monitored user-mode API calls.
        // Reference: https://github.com/outflanknl/Dumpert
        $string2 = /\\Temp\\dumpert/ nocase ascii wide
        // Description: Dumpert. an LSASS memory dumper using direct system calls and API unhooking Recent malware research shows that there is an increase in malware that is using direct system calls to evade user-mode API hooks used by security products. This tool demonstrates the use of direct System Calls and API unhooking and combine these techniques in a proof of concept code which can be used to create a LSASS memory dump using Cobalt Strike. while not touching disk and evading AV/EDR monitored user-mode API calls.
        // Reference: https://github.com/outflanknl/Dumpert
        $string3 = "1ce610dbd4ac4eaf18555046ad6001ecac4245c8d69eb4f3cc9affa10d37bacb" nocase ascii wide
        // Description: Dumpert. an LSASS memory dumper using direct system calls and API unhooking Recent malware research shows that there is an increase in malware that is using direct system calls to evade user-mode API hooks used by security products. This tool demonstrates the use of direct System Calls and API unhooking and combine these techniques in a proof of concept code which can be used to create a LSASS memory dump using Cobalt Strike. while not touching disk and evading AV/EDR monitored user-mode API calls.
        // Reference: https://github.com/outflanknl/Dumpert
        $string4 = "307088B9-2992-4DE7-A57D-9E657B1CE546" nocase ascii wide
        // Description: Dumpert. an LSASS memory dumper using direct system calls and API unhooking Recent malware research shows that there is an increase in malware that is using direct system calls to evade user-mode API hooks used by security products. This tool demonstrates the use of direct System Calls and API unhooking and combine these techniques in a proof of concept code which can be used to create a LSASS memory dump using Cobalt Strike. while not touching disk and evading AV/EDR monitored user-mode API calls.
        // Reference: https://github.com/outflanknl/Dumpert
        $string5 = "31f63c6923ddd1a842839f7ef1d54fec535f94760d89f0a90ad83a19dc906a8c" nocase ascii wide
        // Description: Dumpert. an LSASS memory dumper using direct system calls and API unhooking Recent malware research shows that there is an increase in malware that is using direct system calls to evade user-mode API hooks used by security products. This tool demonstrates the use of direct System Calls and API unhooking and combine these techniques in a proof of concept code which can be used to create a LSASS memory dump using Cobalt Strike. while not touching disk and evading AV/EDR monitored user-mode API calls.
        // Reference: https://github.com/outflanknl/Dumpert
        $string6 = "48fcb3ac5d2ca4147cb46d18b662bc25262988a105fd8c93212297a07af3d615" nocase ascii wide
        // Description: Dumpert. an LSASS memory dumper using direct system calls and API unhooking Recent malware research shows that there is an increase in malware that is using direct system calls to evade user-mode API hooks used by security products. This tool demonstrates the use of direct System Calls and API unhooking and combine these techniques in a proof of concept code which can be used to create a LSASS memory dump using Cobalt Strike. while not touching disk and evading AV/EDR monitored user-mode API calls.
        // Reference: https://github.com/outflanknl/Dumpert
        $string7 = "4bbc3665b5dd41184146e64b1b3d563af181600c9375d3e9d99170684a82a8ce" nocase ascii wide
        // Description: Dumpert. an LSASS memory dumper using direct system calls and API unhooking Recent malware research shows that there is an increase in malware that is using direct system calls to evade user-mode API hooks used by security products. This tool demonstrates the use of direct System Calls and API unhooking and combine these techniques in a proof of concept code which can be used to create a LSASS memory dump using Cobalt Strike. while not touching disk and evading AV/EDR monitored user-mode API calls.
        // Reference: https://github.com/outflanknl/Dumpert
        $string8 = "554F8E48FA40E48E261B91A4F9F1930E099EBF337DFAC826BC41F4E850C4889F" nocase ascii wide
        // Description: Dumpert. an LSASS memory dumper using direct system calls and API unhooking Recent malware research shows that there is an increase in malware that is using direct system calls to evade user-mode API hooks used by security products. This tool demonstrates the use of direct System Calls and API unhooking and combine these techniques in a proof of concept code which can be used to create a LSASS memory dump using Cobalt Strike. while not touching disk and evading AV/EDR monitored user-mode API calls.
        // Reference: https://github.com/outflanknl/Dumpert
        $string9 = "7202dbae30292ab2e370ff0fbcb4cdb5ef765e1e290968f7222d65c24e4645ba" nocase ascii wide
        // Description: Dumpert. an LSASS memory dumper using direct system calls and API unhooking Recent malware research shows that there is an increase in malware that is using direct system calls to evade user-mode API hooks used by security products. This tool demonstrates the use of direct System Calls and API unhooking and combine these techniques in a proof of concept code which can be used to create a LSASS memory dump using Cobalt Strike. while not touching disk and evading AV/EDR monitored user-mode API calls.
        // Reference: https://github.com/outflanknl/Dumpert
        $string10 = "7498456870aa9d28a3ec5fd9bab4838bd4a0a35c2f41ac8da9116326337f8b7e" nocase ascii wide
        // Description: Dumpert. an LSASS memory dumper using direct system calls and API unhooking Recent malware research shows that there is an increase in malware that is using direct system calls to evade user-mode API hooks used by security products. This tool demonstrates the use of direct System Calls and API unhooking and combine these techniques in a proof of concept code which can be used to create a LSASS memory dump using Cobalt Strike. while not touching disk and evading AV/EDR monitored user-mode API calls.
        // Reference: https://github.com/outflanknl/Dumpert
        $string11 = "80086e7ab0990319d4f61b69990eda05ff16dcd836c3b489b2bf8a189bc0c08e" nocase ascii wide
        // Description: Dumpert. an LSASS memory dumper using direct system calls and API unhooking Recent malware research shows that there is an increase in malware that is using direct system calls to evade user-mode API hooks used by security products. This tool demonstrates the use of direct System Calls and API unhooking and combine these techniques in a proof of concept code which can be used to create a LSASS memory dump using Cobalt Strike. while not touching disk and evading AV/EDR monitored user-mode API calls.
        // Reference: https://github.com/outflanknl/Dumpert
        $string12 = "8943acdb8de2a40ca4fd8e1a2f98029aa6e8d78c9f19430b6ac557b6fb8ce4cb" nocase ascii wide
        // Description: Dumpert. an LSASS memory dumper using direct system calls and API unhooking Recent malware research shows that there is an increase in malware that is using direct system calls to evade user-mode API hooks used by security products. This tool demonstrates the use of direct System Calls and API unhooking and combine these techniques in a proof of concept code which can be used to create a LSASS memory dump using Cobalt Strike. while not touching disk and evading AV/EDR monitored user-mode API calls.
        // Reference: https://github.com/outflanknl/Dumpert
        $string13 = "8943acdb8de2a40ca4fd8e1a2f98029aa6e8d78c9f19430b6ac557b6fb8ce4cb" nocase ascii wide
        // Description: Dumpert. an LSASS memory dumper using direct system calls and API unhooking Recent malware research shows that there is an increase in malware that is using direct system calls to evade user-mode API hooks used by security products. This tool demonstrates the use of direct System Calls and API unhooking and combine these techniques in a proof of concept code which can be used to create a LSASS memory dump using Cobalt Strike. while not touching disk and evading AV/EDR monitored user-mode API calls.
        // Reference: https://github.com/outflanknl/Dumpert
        $string14 = "93ade5b0b20ac4c950f3610f96c9f76a8cab972e793ed6364a2f2276965690f8" nocase ascii wide
        // Description: Dumpert. an LSASS memory dumper using direct system calls and API unhooking Recent malware research shows that there is an increase in malware that is using direct system calls to evade user-mode API hooks used by security products. This tool demonstrates the use of direct System Calls and API unhooking and combine these techniques in a proof of concept code which can be used to create a LSASS memory dump using Cobalt Strike. while not touching disk and evading AV/EDR monitored user-mode API calls.
        // Reference: https://github.com/outflanknl/Dumpert
        $string15 = "9a4b0023e443b33d85280eedb510864c42b4146c8e6e5f742444b3eff0aae55f" nocase ascii wide
        // Description: Dumpert. an LSASS memory dumper using direct system calls and API unhooking Recent malware research shows that there is an increase in malware that is using direct system calls to evade user-mode API hooks used by security products. This tool demonstrates the use of direct System Calls and API unhooking and combine these techniques in a proof of concept code which can be used to create a LSASS memory dump using Cobalt Strike. while not touching disk and evading AV/EDR monitored user-mode API calls.
        // Reference: https://github.com/outflanknl/Dumpert
        $string16 = "9b4c57e7b68da80e3949caccaca1742dfdbe31be6f033096f8c9d72a7a0e7947" nocase ascii wide
        // Description: Dumpert. an LSASS memory dumper using direct system calls and API unhooking Recent malware research shows that there is an increase in malware that is using direct system calls to evade user-mode API hooks used by security products. This tool demonstrates the use of direct System Calls and API unhooking and combine these techniques in a proof of concept code which can be used to create a LSASS memory dump using Cobalt Strike. while not touching disk and evading AV/EDR monitored user-mode API calls.
        // Reference: https://github.com/outflanknl/Dumpert
        $string17 = "By Cneeliz @Outflank 2019" nocase ascii wide
        // Description: Dumpert. an LSASS memory dumper using direct system calls and API unhooking Recent malware research shows that there is an increase in malware that is using direct system calls to evade user-mode API hooks used by security products. This tool demonstrates the use of direct System Calls and API unhooking and combine these techniques in a proof of concept code which can be used to create a LSASS memory dump using Cobalt Strike. while not touching disk and evading AV/EDR monitored user-mode API calls.
        // Reference: https://github.com/outflanknl/Dumpert
        $string18 = "c23c160ea84911fa0041045b64551322f282d2d68b5c2689c4bd992c2f7c9267" nocase ascii wide
        // Description: Dumpert. an LSASS memory dumper using direct system calls and API unhooking Recent malware research shows that there is an increase in malware that is using direct system calls to evade user-mode API hooks used by security products. This tool demonstrates the use of direct System Calls and API unhooking and combine these techniques in a proof of concept code which can be used to create a LSASS memory dump using Cobalt Strike. while not touching disk and evading AV/EDR monitored user-mode API calls.
        // Reference: https://github.com/outflanknl/Dumpert
        $string19 = "C7A0003B-98DC-4D57-8F09-5B90AAEFBDF4" nocase ascii wide
        // Description: Dumpert. an LSASS memory dumper using direct system calls and API unhooking Recent malware research shows that there is an increase in malware that is using direct system calls to evade user-mode API hooks used by security products. This tool demonstrates the use of direct System Calls and API unhooking and combine these techniques in a proof of concept code which can be used to create a LSASS memory dump using Cobalt Strike. while not touching disk and evading AV/EDR monitored user-mode API calls.
        // Reference: https://github.com/outflanknl/Dumpert
        $string20 = "Dumpert by Outflank" nocase ascii wide
        // Description: Dumpert. an LSASS memory dumper using direct system calls and API unhooking Recent malware research shows that there is an increase in malware that is using direct system calls to evade user-mode API hooks used by security products. This tool demonstrates the use of direct System Calls and API unhooking and combine these techniques in a proof of concept code which can be used to create a LSASS memory dump using Cobalt Strike. while not touching disk and evading AV/EDR monitored user-mode API calls.
        // Reference: https://github.com/outflanknl/Dumpert
        $string21 = /dumpert\.dmp/ nocase ascii wide
        // Description: Dumpert. an LSASS memory dumper using direct system calls and API unhooking Recent malware research shows that there is an increase in malware that is using direct system calls to evade user-mode API hooks used by security products. This tool demonstrates the use of direct System Calls and API unhooking and combine these techniques in a proof of concept code which can be used to create a LSASS memory dump using Cobalt Strike. while not touching disk and evading AV/EDR monitored user-mode API calls.
        // Reference: https://github.com/outflanknl/Dumpert
        $string22 = /Dumpert\.exe/ nocase ascii wide
        // Description: Dumpert. an LSASS memory dumper using direct system calls and API unhooking Recent malware research shows that there is an increase in malware that is using direct system calls to evade user-mode API hooks used by security products. This tool demonstrates the use of direct System Calls and API unhooking and combine these techniques in a proof of concept code which can be used to create a LSASS memory dump using Cobalt Strike. while not touching disk and evading AV/EDR monitored user-mode API calls.
        // Reference: https://github.com/outflanknl/Dumpert
        $string23 = /Dumpert\.git/ nocase ascii wide
        // Description: Dumpert. an LSASS memory dumper using direct system calls and API unhooking Recent malware research shows that there is an increase in malware that is using direct system calls to evade user-mode API hooks used by security products. This tool demonstrates the use of direct System Calls and API unhooking and combine these techniques in a proof of concept code which can be used to create a LSASS memory dump using Cobalt Strike. while not touching disk and evading AV/EDR monitored user-mode API calls.
        // Reference: https://github.com/outflanknl/Dumpert
        $string24 = "Dumpert-Aggressor" nocase ascii wide
        // Description: Dumpert. an LSASS memory dumper using direct system calls and API unhooking Recent malware research shows that there is an increase in malware that is using direct system calls to evade user-mode API hooks used by security products. This tool demonstrates the use of direct System Calls and API unhooking and combine these techniques in a proof of concept code which can be used to create a LSASS memory dump using Cobalt Strike. while not touching disk and evading AV/EDR monitored user-mode API calls.
        // Reference: https://github.com/outflanknl/Dumpert
        $string25 = "Dumpert-DLL" nocase ascii wide
        // Description: Dumpert. an LSASS memory dumper using direct system calls and API unhooking Recent malware research shows that there is an increase in malware that is using direct system calls to evade user-mode API hooks used by security products. This tool demonstrates the use of direct System Calls and API unhooking and combine these techniques in a proof of concept code which can be used to create a LSASS memory dump using Cobalt Strike. while not touching disk and evading AV/EDR monitored user-mode API calls.
        // Reference: https://github.com/outflanknl/Dumpert
        $string26 = /dumpmethod\.dumpert/ nocase ascii wide
        // Description: Dumpert. an LSASS memory dumper using direct system calls and API unhooking Recent malware research shows that there is an increase in malware that is using direct system calls to evade user-mode API hooks used by security products. This tool demonstrates the use of direct System Calls and API unhooking and combine these techniques in a proof of concept code which can be used to create a LSASS memory dump using Cobalt Strike. while not touching disk and evading AV/EDR monitored user-mode API calls.
        // Reference: https://github.com/outflanknl/Dumpert
        $string27 = "e05b1fa26c9571a7c6111e64a5d710f7bd03fa9795ac68a5f405ba3ac99503e5" nocase ascii wide
        // Description: Dumpert. an LSASS memory dumper using direct system calls and API unhooking Recent malware research shows that there is an increase in malware that is using direct system calls to evade user-mode API hooks used by security products. This tool demonstrates the use of direct System Calls and API unhooking and combine these techniques in a proof of concept code which can be used to create a LSASS memory dump using Cobalt Strike. while not touching disk and evading AV/EDR monitored user-mode API calls.
        // Reference: https://github.com/outflanknl/Dumpert
        $string28 = "fe1e030312bcb26de66eea442200e4d73ff88307784fe6f1f72f776efcd5e9be" nocase ascii wide
        // Description: Dumpert. an LSASS memory dumper using direct system calls and API unhooking Recent malware research shows that there is an increase in malware that is using direct system calls to evade user-mode API hooks used by security products. This tool demonstrates the use of direct System Calls and API unhooking and combine these techniques in a proof of concept code which can be used to create a LSASS memory dump using Cobalt Strike. while not touching disk and evading AV/EDR monitored user-mode API calls.
        // Reference: https://github.com/outflanknl/Dumpert
        $string29 = "fe1e030312bcb26de66eea442200e4d73ff88307784fe6f1f72f776efcd5e9be" nocase ascii wide
        // Description: Dumpert. an LSASS memory dumper using direct system calls and API unhooking Recent malware research shows that there is an increase in malware that is using direct system calls to evade user-mode API hooks used by security products. This tool demonstrates the use of direct System Calls and API unhooking and combine these techniques in a proof of concept code which can be used to create a LSASS memory dump using Cobalt Strike. while not touching disk and evading AV/EDR monitored user-mode API calls.
        // Reference: https://github.com/outflanknl/Dumpert
        $string30 = "Lsass minidump can be imported in " nocase ascii wide
        // Description: Dumpert. an LSASS memory dumper using direct system calls and API unhooking Recent malware research shows that there is an increase in malware that is using direct system calls to evade user-mode API hooks used by security products. This tool demonstrates the use of direct System Calls and API unhooking and combine these techniques in a proof of concept code which can be used to create a LSASS memory dump using Cobalt Strike. while not touching disk and evading AV/EDR monitored user-mode API calls.
        // Reference: https://github.com/outflanknl/Dumpert
        $string31 = "Outflank-Dumpert" nocase ascii wide
        // Description: Dumpert. an LSASS memory dumper using direct system calls and API unhooking Recent malware research shows that there is an increase in malware that is using direct system calls to evade user-mode API hooks used by security products. This tool demonstrates the use of direct System Calls and API unhooking and combine these techniques in a proof of concept code which can be used to create a LSASS memory dump using Cobalt Strike. while not touching disk and evading AV/EDR monitored user-mode API calls.
        // Reference: https://github.com/outflanknl/Dumpert
        $string32 = "outflanknl/Dumpert" nocase ascii wide
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
