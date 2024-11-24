rule NTLMInjector
{
    meta:
        description = "Detection patterns for the tool 'NTLMInjector' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "NTLMInjector"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: restore the user password after a password reset (get the previous hash with DCSync)
        // Reference: https://github.com/vletoux/NTLMInjector
        $string1 = /\/NTLMInjector\.git/ nocase ascii wide
        // Description: restore the user password after a password reset (get the previous hash with DCSync)
        // Reference: https://github.com/vletoux/NTLMInjector
        $string2 = /\/SetNTLM\.ps1/ nocase ascii wide
        // Description: restore the user password after a password reset (get the previous hash with DCSync)
        // Reference: https://github.com/vletoux/NTLMInjector
        $string3 = /\\SetNTLM\.ps1/ nocase ascii wide
        // Description: restore the user password after a password reset (get the previous hash with DCSync)
        // Reference: https://github.com/vletoux/NTLMInjector
        $string4 = "197f8806b3b467c66ad64b187f831f10ddd71695d61a42344ae617ee62e62faa" nocase ascii wide
        // Description: restore the user password after a password reset (get the previous hash with DCSync)
        // Reference: https://github.com/vletoux/NTLMInjector
        $string5 = "ce4255704740f395be5713b049b97814ce537c440b1249850bcb62794dcc7f56" nocase ascii wide
        // Description: restore the user password after a password reset (get the previous hash with DCSync)
        // Reference: https://github.com/vletoux/NTLMInjector
        $string6 = "namespace NTLMInjector" nocase ascii wide
        // Description: restore the user password after a password reset (get the previous hash with DCSync)
        // Reference: https://github.com/vletoux/NTLMInjector
        $string7 = /NTLMInjector\.ps1/ nocase ascii wide
        // Description: restore the user password after a password reset (get the previous hash with DCSync)
        // Reference: https://github.com/vletoux/NTLMInjector
        $string8 = "public class NTLMInjector" nocase ascii wide
        // Description: restore the user password after a password reset (get the previous hash with DCSync)
        // Reference: https://github.com/vletoux/NTLMInjector
        $string9 = "vletoux/NTLMInjector" nocase ascii wide
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
