rule ivy
{
    meta:
        description = "Detection patterns for the tool 'ivy' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ivy"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Ivy is a payload creation framework for the execution of arbitrary VBA (macro) source code directly in memory
        // Reference: https://github.com/optiv/Ivy
        $string1 = /\s\-Ix64\s.{0,100}\.bin\s\-Ix86\s.{0,100}\.bin\s\-P\sInject\s\-O\s.{0,100}\.png\s\-stageless/ nocase ascii wide
        // Description: Ivy is a payload creation framework for the execution of arbitrary VBA (macro) source code directly in memory
        // Reference: https://github.com/optiv/Ivy
        $string2 = /\s\-Ix64\s.{0,100}\.bin\s\-Ix86\s.{0,100}\.bin\s\-P\sLocal\s\-O\s.{0,100}\.hta\s\-url\shttp\:.{0,100}\s\-delivery\shta\s\-stageless/ nocase ascii wide
        // Description: Ivy is a payload creation framework for the execution of arbitrary VBA (macro) source code directly in memory
        // Reference: https://github.com/optiv/Ivy
        $string3 = /\s\-Ix64\s.{0,100}\.bin\s\-Ix86\s.{0,100}\.bin\s\-P\sLocal\s\-O\s.{0,100}\.js\s\-url\shttp.{0,100}\s\-delivery\sbits\s\-stageless/ nocase ascii wide
        // Description: Ivy is a payload creation framework for the execution of arbitrary VBA (macro) source code directly in memory
        // Reference: https://github.com/optiv/Ivy
        $string4 = /\s\-Ix64\s.{0,100}\.bin\s\-Ix86\s.{0,100}\.bin\s\-P\sLocal\s\-O\s.{0,100}\.txt\s\-url\shttp.{0,100}\s\-delivery\smacro\s\-stageless/ nocase ascii wide
        // Description: Ivy is a payload creation framework for the execution of arbitrary VBA (macro) source code directly in memory
        // Reference: https://github.com/optiv/Ivy
        $string5 = /\s\-Ix64\s.{0,100}\.bin\s\-Ix86\s.{0,100}\.bin\s\-P\sLocal\s\-O\s.{0,100}\.xsl\s\-url\shttp.{0,100}\s\-delivery\sxsl\s\-stageless/ nocase ascii wide
        // Description: Ivy is a payload creation framework for the execution of arbitrary VBA (macro) source code directly in memory
        // Reference: https://github.com/optiv/Ivy
        $string6 = /\s\-Ix64\s.{0,100}\.c\s\-Ix86\s.{0,100}\.c\s\-P\sLocal\s\-O\s.{0,100}\.js/ nocase ascii wide
        // Description: Ivy is a payload creation framework for the execution of arbitrary VBA (macro) source code directly in memory
        // Reference: https://github.com/optiv/Ivy
        $string7 = /\s\-Ix64\s.{0,100}\.vba\s\-Ix86\s.{0,100}\.vba\s\-P\sInject\s\-O\s/ nocase ascii wide
        // Description: Ivy is a payload creation framework for the execution of arbitrary VBA (macro) source code directly in memory
        // Reference: https://github.com/optiv/Ivy
        $string8 = /\s\-stageless\s\-Ix64\s.{0,100}\.bin\s\-Ix86\s.{0,100}\.bin\s\-P\sInject\s\-O\s.{0,100}\.js/ nocase ascii wide
        // Description: Ivy is a payload creation framework for the execution of arbitrary VBA (macro) source code directly in memory
        // Reference: https://github.com/optiv/Ivy
        $string9 = /\s\-stageless\s\-Ix64\s.{0,100}\.bin\s\-Ix86\s.{0,100}\.bin\s\-P\sInject\s\-process64\s.{0,100}\.exe\s\-O\s.{0,100}\.js/ nocase ascii wide
        // Description: Ivy is a payload creation framework for the execution of arbitrary VBA (macro) source code directly in memory
        // Reference: https://github.com/optiv/Ivy
        $string10 = /\s\-stageless\s\-Ix64\s.{0,100}\.bin\s\-Ix86\s.{0,100}\.bin\s\-P\sInject\s\-unhook\s\-O\s.{0,100}\.js/ nocase ascii wide
        // Description: Ivy is a payload creation framework for the execution of arbitrary VBA (macro) source code directly in memory
        // Reference: https://github.com/optiv/Ivy
        $string11 = /\s\-stageless\s\-Ix64\s.{0,100}\.bin\s\-Ix86\s.{0,100}\.bin\s\-P\sLocal\s\-O\s.{0,100}\.js/ nocase ascii wide
        // Description: Ivy is a payload creation framework for the execution of arbitrary VBA (macro) source code directly in memory
        // Reference: https://github.com/optiv/Ivy
        $string12 = /\s\-stageless\s\-Ix64\s.{0,100}\.bin\s\-Ix86\s.{0,100}\.bin\s\-P\sLocal\s\-unhook\s\-O\s.{0,100}\.js/ nocase ascii wide
        // Description: Ivy is a payload creation framework for the execution of arbitrary VBA (macro) source code directly in memory
        // Reference: https://github.com/optiv/Ivy
        $string13 = /\.\/Ivy\s\-/
        // Description: Ivy is a payload creation framework for the execution of arbitrary VBA (macro) source code directly in memory
        // Reference: https://github.com/optiv/Ivy
        $string14 = "/Ivy/Cryptor" nocase ascii wide
        // Description: Ivy is a payload creation framework for the execution of arbitrary VBA (macro) source code directly in memory
        // Reference: https://github.com/optiv/Ivy
        $string15 = "/Ivy/Loader/" nocase ascii wide
        // Description: Ivy is a payload creation framework for the execution of arbitrary VBA (macro) source code directly in memory
        // Reference: https://github.com/optiv/Ivy
        $string16 = /\\Ivy\\Cryptor/ nocase ascii wide
        // Description: Ivy is a payload creation framework for the execution of arbitrary VBA (macro) source code directly in memory
        // Reference: https://github.com/optiv/Ivy
        $string17 = /\\Ivy\\Loader\\/ nocase ascii wide
        // Description: Ivy is a payload creation framework for the execution of arbitrary VBA (macro) source code directly in memory
        // Reference: https://github.com/optiv/Ivy
        $string18 = "7267a9321dd7ab890af5892975e257f89b2e53c70216c3708be9b0418e6b470e" nocase ascii wide
        // Description: Ivy is a payload creation framework for the execution of arbitrary VBA (macro) source code directly in memory
        // Reference: https://github.com/optiv/Ivy
        $string19 = /go\sbuild\sIvy\.go/ nocase ascii wide
        // Description: Ivy is a payload creation framework for the execution of arbitrary VBA (macro) source code directly in memory
        // Reference: https://github.com/optiv/Ivy
        $string20 = /Ivy_1.{0,100}_darwin_amd64/
        // Description: Ivy is a payload creation framework for the execution of arbitrary VBA (macro) source code directly in memory
        // Reference: https://github.com/optiv/Ivy
        $string21 = /Ivy_1.{0,100}_linux_amd64/
        // Description: Ivy is a payload creation framework for the execution of arbitrary VBA (macro) source code directly in memory
        // Reference: https://github.com/optiv/Ivy
        $string22 = /Ivy_1.{0,100}_windows_amd64\.exe/ nocase ascii wide
        // Description: Ivy is a payload creation framework for the execution of arbitrary VBA (macro) source code directly in memory
        // Reference: https://github.com/optiv/Ivy
        $string23 = /Ivy\-main\.zip/ nocase ascii wide
        // Description: Ivy is a payload creation framework for the execution of arbitrary VBA (macro) source code directly in memory
        // Reference: https://github.com/optiv/Ivy
        $string24 = /optiv\/Ivy\.git/ nocase ascii wide
        // Description: Ivy is a payload creation framework for the execution of arbitrary VBA (macro) source code directly in memory
        // Reference: https://github.com/optiv/Ivy
        $string25 = "Tylous/Ivy" nocase ascii wide
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
