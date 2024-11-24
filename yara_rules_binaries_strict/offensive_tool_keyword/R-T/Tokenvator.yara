rule Tokenvator
{
    meta:
        description = "Detection patterns for the tool 'Tokenvator' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Tokenvator"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A tool to elevate privilege with Windows Tokens
        // Reference: https://github.com/0xbadjuju/Tokenvator
        $string1 = /\sClone_Token\s\/Process\:.{0,100}\s\/Command\:/ nocase ascii wide
        // Description: A tool to elevate privilege with Windows Tokens
        // Reference: https://github.com/0xbadjuju/Tokenvator
        $string2 = /\ssteal_token\s\/process\:.{0,100}\s\/command\:/ nocase ascii wide
        // Description: A tool to elevate privilege with Windows Tokens
        // Reference: https://github.com/0xbadjuju/Tokenvator
        $string3 = " tokenvator " nocase ascii wide
        // Description: A tool to elevate privilege with Windows Tokens
        // Reference: https://github.com/0xbadjuju/Tokenvator
        $string4 = /\/MonkeyWorks\.git/ nocase ascii wide
        // Description: A tool to elevate privilege with Windows Tokens
        // Reference: https://github.com/0xbadjuju/Tokenvator
        $string5 = "/ServiceName:TokenDriver" nocase ascii wide
        // Description: A tool to elevate privilege with Windows Tokens
        // Reference: https://github.com/0xbadjuju/Tokenvator
        $string6 = "/Tokenvator/" nocase ascii wide
        // Description: A tool to elevate privilege with Windows Tokens
        // Reference: https://github.com/0xbadjuju/Tokenvator
        $string7 = /\\KernelTokens\.sys/ nocase ascii wide
        // Description: A tool to elevate privilege with Windows Tokens
        // Reference: https://github.com/0xbadjuju/Tokenvator
        $string8 = /\\Tokenvator\\/ nocase ascii wide
        // Description: A tool to elevate privilege with Windows Tokens
        // Reference: https://github.com/0xbadjuju/Tokenvator
        $string9 = "0xbadjuju/Tokenvator" nocase ascii wide
        // Description: A tool to elevate privilege with Windows Tokens
        // Reference: https://github.com/0xbadjuju/Tokenvator
        $string10 = /Add_Privilege\s\/Process\:.{0,100}\s\/Privilege\:/ nocase ascii wide
        // Description: A tool to elevate privilege with Windows Tokens
        // Reference: https://github.com/0xbadjuju/Tokenvator
        $string11 = /BypassUAC\s.{0,100}\.exe/ nocase ascii wide
        // Description: A tool to elevate privilege with Windows Tokens
        // Reference: https://github.com/0xbadjuju/Tokenvator
        $string12 = /Disable_Privilege\s\/Process\:.{0,100}\s\/Privilege\:/ nocase ascii wide
        // Description: A tool to elevate privilege with Windows Tokens
        // Reference: https://github.com/0xbadjuju/Tokenvator
        $string13 = /Enable_Privilege\s\/Process\:.{0,100}\s\/Privilege\:/ nocase ascii wide
        // Description: A tool to elevate privilege with Windows Tokens
        // Reference: https://github.com/0xbadjuju/Tokenvator
        $string14 = "Enumeration/DesktopACL" nocase ascii wide
        // Description: A tool to elevate privilege with Windows Tokens
        // Reference: https://github.com/0xbadjuju/Tokenvator
        $string15 = /Enumeration\\DesktopAC/ nocase ascii wide
        // Description: A tool to elevate privilege with Windows Tokens
        // Reference: https://github.com/0xbadjuju/Tokenvator
        $string16 = "List_Privileges /Process:powershell" nocase ascii wide
        // Description: A tool to elevate privilege with Windows Tokens
        // Reference: https://github.com/0xbadjuju/Tokenvator
        $string17 = "Nuke_Privileges /Process:" nocase ascii wide
        // Description: A tool to elevate privilege with Windows Tokens
        // Reference: https://github.com/0xbadjuju/Tokenvator
        $string18 = /Plugins\\AccessTokens\\TokenDriver/ nocase ascii wide
        // Description: A tool to elevate privilege with Windows Tokens
        // Reference: https://github.com/0xbadjuju/Tokenvator
        $string19 = /Plugins\\AccessTokens\\TokenManipulation/ nocase ascii wide
        // Description: A tool to elevate privilege with Windows Tokens
        // Reference: https://github.com/0xbadjuju/Tokenvator
        $string20 = /Plugins\\Execution\\PSExec/ nocase ascii wide
        // Description: A tool to elevate privilege with Windows Tokens
        // Reference: https://github.com/0xbadjuju/Tokenvator
        $string21 = /Remove_Privilege\s\/Process\:.{0,100}\s\/Privilege\:/ nocase ascii wide
        // Description: A tool to elevate privilege with Windows Tokens
        // Reference: https://github.com/0xbadjuju/Tokenvator
        $string22 = "Steal_Pipe_Token /PipeName" nocase ascii wide
        // Description: A tool to alter privilege with Windows Tokens
        // Reference: https://github.com/0xbadjuju/Tokenvator
        $string23 = "Tokenvator" nocase ascii wide
        // Description: A tool to elevate privilege with Windows Tokens
        // Reference: https://github.com/0xbadjuju/Tokenvator
        $string24 = /Tokenvator.{0,100}\.exe/ nocase ascii wide
        // Description: A tool to elevate privilege with Windows Tokens
        // Reference: https://github.com/0xbadjuju/Tokenvator
        $string25 = /Tokenvator\.csproj/ nocase ascii wide
        // Description: A tool to elevate privilege with Windows Tokens
        // Reference: https://github.com/0xbadjuju/Tokenvator
        $string26 = /Tokenvator\.exe/ nocase ascii wide
        // Description: A tool to elevate privilege with Windows Tokens
        // Reference: https://github.com/0xbadjuju/Tokenvator
        $string27 = /Tokenvator\.git/ nocase ascii wide
        // Description: A tool to elevate privilege with Windows Tokens
        // Reference: https://github.com/0xbadjuju/Tokenvator
        $string28 = /Tokenvator\.pdb/ nocase ascii wide
        // Description: A tool to elevate privilege with Windows Tokens
        // Reference: https://github.com/0xbadjuju/Tokenvator
        $string29 = /Tokenvator\.Plugins/ nocase ascii wide
        // Description: A tool to elevate privilege with Windows Tokens
        // Reference: https://github.com/0xbadjuju/Tokenvator
        $string30 = /Tokenvator\.Resources/ nocase ascii wide
        // Description: A tool to elevate privilege with Windows Tokens
        // Reference: https://github.com/0xbadjuju/Tokenvator
        $string31 = /Tokenvator\.sln/ nocase ascii wide
        // Description: A tool to elevate privilege with Windows Tokens
        // Reference: https://github.com/0xbadjuju/Tokenvator
        $string32 = "Tokenvator/MonkeyWorks" nocase ascii wide
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
