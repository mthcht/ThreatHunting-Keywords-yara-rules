rule Token_Impersonation
{
    meta:
        description = "Detection patterns for the tool 'Token-Impersonation' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Token-Impersonation"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Make a Token (local admin rights not required) or Steal the Token of the specified Process ID (local admin rights required)
        // Reference: https://github.com/Leo4j/Token-Impersonation
        $string1 = " -Steal -ProcessID " nocase ascii wide
        // Description: Make a Token (local admin rights not required) or Steal the Token of the specified Process ID (local admin rights required)
        // Reference: https://github.com/Leo4j/Token-Impersonation
        $string2 = /\sToken\-Impersonation\.ps1/ nocase ascii wide
        // Description: Make a Token (local admin rights not required) or Steal the Token of the specified Process ID (local admin rights required)
        // Reference: https://github.com/Leo4j/Token-Impersonation
        $string3 = /\$StealToken/ nocase ascii wide
        // Description: Make a Token (local admin rights not required) or Steal the Token of the specified Process ID (local admin rights required)
        // Reference: https://github.com/Leo4j/Token-Impersonation
        $string4 = /\/Token\-Impersonation\.git/ nocase ascii wide
        // Description: Make a Token (local admin rights not required) or Steal the Token of the specified Process ID (local admin rights required)
        // Reference: https://github.com/Leo4j/Token-Impersonation
        $string5 = /\/Token\-Impersonation\.ps1/ nocase ascii wide
        // Description: Make a Token (local admin rights not required) or Steal the Token of the specified Process ID (local admin rights required)
        // Reference: https://github.com/Leo4j/Token-Impersonation
        $string6 = /\[\+\]\sImpersonation\ssuccessful\susing\stoken\sfrom\sPID\s/ nocase ascii wide
        // Description: Make a Token (local admin rights not required) or Steal the Token of the specified Process ID (local admin rights required)
        // Reference: https://github.com/Leo4j/Token-Impersonation
        $string7 = /\\Token\-Impersonation\.ps1/ nocase ascii wide
        // Description: Make a Token (local admin rights not required) or Steal the Token of the specified Process ID (local admin rights required)
        // Reference: https://github.com/Leo4j/Token-Impersonation
        $string8 = "42e10ec6f9a5276060bade151ccd929325daa8ac8910ee26de5e6eebe10f77aa" nocase ascii wide
        // Description: Make a Token (local admin rights not required) or Steal the Token of the specified Process ID (local admin rights required)
        // Reference: https://github.com/Leo4j/Token-Impersonation
        $string9 = "Leo4j/Token-Impersonation" nocase ascii wide
        // Description: Make a Token (local admin rights not required) or Steal the Token of the specified Process ID (local admin rights required)
        // Reference: https://github.com/Leo4j/Token-Impersonation
        $string10 = "Token-Impersonation -MakeToken" nocase ascii wide
        // Description: Make a Token (local admin rights not required) or Steal the Token of the specified Process ID (local admin rights required)
        // Reference: https://github.com/Leo4j/Token-Impersonation
        $string11 = "Token-Impersonation -Rev2Self" nocase ascii wide
        // Description: Make a Token (local admin rights not required) or Steal the Token of the specified Process ID (local admin rights required)
        // Reference: https://github.com/Leo4j/Token-Impersonation
        $string12 = "Token-Impersonation -Steal" nocase ascii wide
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
