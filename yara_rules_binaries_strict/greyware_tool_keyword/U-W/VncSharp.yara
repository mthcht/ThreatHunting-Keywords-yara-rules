rule VncSharp
{
    meta:
        description = "Detection patterns for the tool 'VncSharp' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "VncSharp"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: VncSharp is a GPL implementation of the VNC Remote Framebuffer (RFB) Protocol for the .NET Framework
        // Reference: https://github.com/humphd/VncSharp
        $string1 = /\/VncSharp\.exe/ nocase ascii wide
        // Description: VncSharp is a GPL implementation of the VNC Remote Framebuffer (RFB) Protocol for the .NET Framework
        // Reference: https://github.com/humphd/VncSharp
        $string2 = /\/VncSharp\.git/ nocase ascii wide
        // Description: VncSharp is a GPL implementation of the VNC Remote Framebuffer (RFB) Protocol for the .NET Framework
        // Reference: https://github.com/humphd/VncSharp
        $string3 = /\\VncSharp\.exe/ nocase ascii wide
        // Description: VncSharp is a GPL implementation of the VNC Remote Framebuffer (RFB) Protocol for the .NET Framework
        // Reference: https://github.com/humphd/VncSharp
        $string4 = /\\VncSharp\.sln/ nocase ascii wide
        // Description: VncSharp is a GPL implementation of the VNC Remote Framebuffer (RFB) Protocol for the .NET Framework
        // Reference: https://github.com/humphd/VncSharp
        $string5 = "73e83646-1d53-4dec-950a-a48559e438e8" nocase ascii wide
        // Description: VncSharp is a GPL implementation of the VNC Remote Framebuffer (RFB) Protocol for the .NET Framework
        // Reference: https://github.com/humphd/VncSharp
        $string6 = "dfedf8e6a6cdb480ee00545da5e7d5370b5b7057d0b274f3a6f9cf4a192a87e6" nocase ascii wide
        // Description: VncSharp is a GPL implementation of the VNC Remote Framebuffer (RFB) Protocol for the .NET Framework
        // Reference: https://github.com/humphd/VncSharp
        $string7 = "E0695F0F-0FAF-44BC-AE55-A1FCBFE70271" nocase ascii wide
        // Description: VncSharp is a GPL implementation of the VNC Remote Framebuffer (RFB) Protocol for the .NET Framework
        // Reference: https://github.com/humphd/VncSharp
        $string8 = "e7f6c011776e8db7cd330b54174fd76f7d0216b612387a5ffcfb81e6f0919683" nocase ascii wide
        // Description: VncSharp is a GPL implementation of the VNC Remote Framebuffer (RFB) Protocol for the .NET Framework
        // Reference: https://github.com/humphd/VncSharp
        $string9 = "humphd/VncSharp" nocase ascii wide
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
