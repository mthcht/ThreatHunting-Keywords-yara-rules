rule ShellGen
{
    meta:
        description = "Detection patterns for the tool 'ShellGen' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ShellGen"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: PowerShell script to generate ShellCode in various formats
        // Reference: https://github.com/Leo4j/ShellGen
        $string1 = /\sShellGen\.ps1/ nocase ascii wide
        // Description: PowerShell script to generate ShellCode in various formats
        // Reference: https://github.com/Leo4j/ShellGen
        $string2 = /\$B64PwshCommand/ nocase ascii wide
        // Description: PowerShell script to generate ShellCode in various formats
        // Reference: https://github.com/Leo4j/ShellGen
        $string3 = /\$shellcode\s\+\=\s0x65\,0x48\,0x8b\,0x42\,0x60/ nocase ascii wide
        // Description: PowerShell script to generate ShellCode in various formats
        // Reference: https://github.com/Leo4j/ShellGen
        $string4 = /\/ShellGen\.git/ nocase ascii wide
        // Description: PowerShell script to generate ShellCode in various formats
        // Reference: https://github.com/Leo4j/ShellGen
        $string5 = /\/ShellGen\.ps1/ nocase ascii wide
        // Description: PowerShell script to generate ShellCode in various formats
        // Reference: https://github.com/Leo4j/ShellGen
        $string6 = /\\ShellGen\.ps1/ nocase ascii wide
        // Description: PowerShell script to generate ShellCode in various formats
        // Reference: https://github.com/Leo4j/ShellGen
        $string7 = /\\ShellGen\-main\.zip/ nocase ascii wide
        // Description: PowerShell script to generate ShellCode in various formats
        // Reference: https://github.com/Leo4j/ShellGen
        $string8 = "59c03a973a4c6ad7327812d568a8bcdd9c21af006853ce459014183bef699a24" nocase ascii wide
        // Description: PowerShell script to generate ShellCode in various formats
        // Reference: https://github.com/Leo4j/ShellGen
        $string9 = "Leo4j/ShellGen" nocase ascii wide
        // Description: PowerShell script to generate ShellCode in various formats
        // Reference: https://github.com/Leo4j/ShellGen
        $string10 = "ShellGen -x64 -B64PwshCommand " nocase ascii wide
        // Description: PowerShell script to generate ShellCode in various formats
        // Reference: https://github.com/Leo4j/ShellGen
        $string11 = "ShellGen -x64 -CmdCommand " nocase ascii wide
        // Description: PowerShell script to generate ShellCode in various formats
        // Reference: https://github.com/Leo4j/ShellGen
        $string12 = "ShellGen -x64 -PwshCommand " nocase ascii wide

    condition:
        any of them
}
