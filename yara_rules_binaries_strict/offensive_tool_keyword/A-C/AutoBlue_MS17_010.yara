rule AutoBlue_MS17_010
{
    meta:
        description = "Detection patterns for the tool 'AutoBlue-MS17-010' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "AutoBlue-MS17-010"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: automated exploit code for MS17-010
        // Reference: https://github.com/3ndG4me/AutoBlue-MS17-010
        $string1 = /\/AutoBlue\-MS17\-010\.git/ nocase ascii wide
        // Description: automated exploit code for MS17-010
        // Reference: https://github.com/3ndG4me/AutoBlue-MS17-010
        $string2 = /\/eternal_checker\.py/ nocase ascii wide
        // Description: automated exploit code for MS17-010
        // Reference: https://github.com/3ndG4me/AutoBlue-MS17-010
        $string3 = /\/zzz_exploit\.py/ nocase ascii wide
        // Description: automated exploit code for MS17-010
        // Reference: https://github.com/3ndG4me/AutoBlue-MS17-010
        $string4 = /\\AutoBlue\-MS17\-010\-main/ nocase ascii wide
        // Description: automated exploit code for MS17-010
        // Reference: https://github.com/3ndG4me/AutoBlue-MS17-010
        $string5 = "0ad2c8d20a383ac7007bb531672f8cbb9fe945b8d32eefa061b4ead09ff92ce3" nocase ascii wide
        // Description: automated exploit code for MS17-010
        // Reference: https://github.com/3ndG4me/AutoBlue-MS17-010
        $string6 = "1008626761b65900ab77833ff6a2a3e2a4d8a7a4eab1e956d477d951f1edd28e" nocase ascii wide
        // Description: automated exploit code for MS17-010
        // Reference: https://github.com/3ndG4me/AutoBlue-MS17-010
        $string7 = "2d93db2abb0ea20a402c5d62e610e36d1957069b8612f7fd05d6be0a1d362c3b" nocase ascii wide
        // Description: automated exploit code for MS17-010
        // Reference: https://github.com/3ndG4me/AutoBlue-MS17-010
        $string8 = "3ndG4me/AutoBlue-MS17-010" nocase ascii wide
        // Description: automated exploit code for MS17-010
        // Reference: https://github.com/3ndG4me/AutoBlue-MS17-010
        $string9 = "4be7282a5c184870c130913381641c2c531d773eec25fc810394fca9ec9c386c" nocase ascii wide
        // Description: automated exploit code for MS17-010
        // Reference: https://github.com/3ndG4me/AutoBlue-MS17-010
        $string10 = "5649329377ee03a1aace70be74650290f8d6bb597351daf62d1a6a4a37db53cb" nocase ascii wide
        // Description: automated exploit code for MS17-010
        // Reference: https://github.com/3ndG4me/AutoBlue-MS17-010
        $string11 = "89d678050ee670535a84b9e38557f626b1c704a9998e528a58e7cee830378283" nocase ascii wide
        // Description: automated exploit code for MS17-010
        // Reference: https://github.com/3ndG4me/AutoBlue-MS17-010
        $string12 = "b5822ac44575655904ac07d44997d0c552a13786e2962ad6fe4813b8146e679e" nocase ascii wide
        // Description: automated exploit code for MS17-010
        // Reference: https://github.com/3ndG4me/AutoBlue-MS17-010
        $string13 = /c\:\\pwned\.txt/ nocase ascii wide
        // Description: automated exploit code for MS17-010
        // Reference: https://github.com/3ndG4me/AutoBlue-MS17-010
        $string14 = /c\:\\pwned_exec\.txt/ nocase ascii wide
        // Description: automated exploit code for MS17-010
        // Reference: https://github.com/3ndG4me/AutoBlue-MS17-010
        $string15 = "d71724687c2914d5e68596f5951d1a94fa511dd2cb57f7fbc39f771a6ec43ae7" nocase ascii wide
        // Description: automated exploit code for MS17-010
        // Reference: https://github.com/3ndG4me/AutoBlue-MS17-010
        $string16 = "echo msfvenom -p windows" nocase ascii wide
        // Description: automated exploit code for MS17-010
        // Reference: https://github.com/3ndG4me/AutoBlue-MS17-010
        $string17 = "Eternal Blue Windows Shellcode Compiler" nocase ascii wide
        // Description: automated exploit code for MS17-010
        // Reference: https://github.com/3ndG4me/AutoBlue-MS17-010
        $string18 = /eternalblue_exploit10\.py/ nocase ascii wide
        // Description: automated exploit code for MS17-010
        // Reference: https://github.com/3ndG4me/AutoBlue-MS17-010
        $string19 = /eternalblue_exploit7\.py/ nocase ascii wide
        // Description: automated exploit code for MS17-010
        // Reference: https://github.com/3ndG4me/AutoBlue-MS17-010
        $string20 = /eternalblue_exploit8\.py/ nocase ascii wide
        // Description: automated exploit code for MS17-010
        // Reference: https://github.com/3ndG4me/AutoBlue-MS17-010
        $string21 = /eternalblue_kshellcode_x64\.asm/ nocase ascii wide
        // Description: automated exploit code for MS17-010
        // Reference: https://github.com/3ndG4me/AutoBlue-MS17-010
        $string22 = /eternalblue_kshellcode_x86\.asm/ nocase ascii wide
        // Description: automated exploit code for MS17-010
        // Reference: https://github.com/3ndG4me/AutoBlue-MS17-010
        $string23 = /eternalblue_poc\.py/ nocase ascii wide
        // Description: automated exploit code for MS17-010
        // Reference: https://github.com/3ndG4me/AutoBlue-MS17-010
        $string24 = /eternalblue_sc_merge\.py/ nocase ascii wide
        // Description: automated exploit code for MS17-010
        // Reference: https://github.com/3ndG4me/AutoBlue-MS17-010
        $string25 = "Generating x64 meterpreter shell" nocase ascii wide
        // Description: automated exploit code for MS17-010
        // Reference: https://github.com/3ndG4me/AutoBlue-MS17-010
        $string26 = "Generating x86 meterpreter shell" nocase ascii wide
        // Description: automated exploit code for MS17-010
        // Reference: https://github.com/3ndG4me/AutoBlue-MS17-010
        $string27 = "MERGING SHELLCODE WOOOO!!!" nocase ascii wide
        // Description: automated exploit code for MS17-010
        // Reference: https://github.com/3ndG4me/AutoBlue-MS17-010
        $string28 = "set PAYLOAD windows/x64/meterpreter_reverse_tcp" nocase ascii wide
        // Description: automated exploit code for MS17-010
        // Reference: https://github.com/3ndG4me/AutoBlue-MS17-010
        $string29 = "set PAYLOAD windows/x64/shell/reverse_tcp" nocase ascii wide
        // Description: automated exploit code for MS17-010
        // Reference: https://github.com/3ndG4me/AutoBlue-MS17-010
        $string30 = /You\scan\'t\sCD\sunder\sSMBEXEC\.\sUse\sfull\spaths/ nocase ascii wide
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
