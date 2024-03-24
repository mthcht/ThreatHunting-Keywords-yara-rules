rule bypass_clm
{
    meta:
        description = "Detection patterns for the tool 'bypass-clm' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "bypass-clm"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: PowerShell Constrained Language Mode Bypass
        // Reference: https://github.com/calebstewart/bypass-clm
        $string1 = /\"bypass\-clm\"/ nocase ascii wide
        // Description: PowerShell Constrained Language Mode Bypass
        // Reference: https://github.com/calebstewart/bypass-clm
        $string2 = /\/bypass\-clm\.exe/ nocase ascii wide
        // Description: PowerShell Constrained Language Mode Bypass
        // Reference: https://github.com/calebstewart/bypass-clm
        $string3 = /\/bypass\-clm\.git/ nocase ascii wide
        // Description: PowerShell Constrained Language Mode Bypass
        // Reference: https://github.com/calebstewart/bypass-clm
        $string4 = /\\bypass\-clm\.exe/ nocase ascii wide
        // Description: PowerShell Constrained Language Mode Bypass
        // Reference: https://github.com/calebstewart/bypass-clm
        $string5 = /\\bypass\-clm\.sln/ nocase ascii wide
        // Description: PowerShell Constrained Language Mode Bypass
        // Reference: https://github.com/calebstewart/bypass-clm
        $string6 = /\\bypass\-clm\\Program\.cs/ nocase ascii wide
        // Description: PowerShell Constrained Language Mode Bypass
        // Reference: https://github.com/calebstewart/bypass-clm
        $string7 = /\\Tasks\\bypass\-clm/ nocase ascii wide
        // Description: PowerShell Constrained Language Mode Bypass
        // Reference: https://github.com/calebstewart/bypass-clm
        $string8 = /\\Windows\\Microsoft\.NET\\.{0,1000}\\InstallUtil\.exe\s\/logfile\=\s\/LogToConsole\=false\s\/U\s.{0,1000}\:\\Windows\\Tasks\\/ nocase ascii wide
        // Description: PowerShell Constrained Language Mode Bypass
        // Reference: https://github.com/calebstewart/bypass-clm
        $string9 = /0b1a6a5a3e7a22a2f68a7b2b83b33117a63f0d6337dddb3d41b250a995210d79/ nocase ascii wide
        // Description: PowerShell Constrained Language Mode Bypass
        // Reference: https://github.com/calebstewart/bypass-clm
        $string10 = /C8D738E6\-8C30\-4715\-8AE5\-6A8FBFE770A7/ nocase ascii wide
        // Description: PowerShell Constrained Language Mode Bypass
        // Reference: https://github.com/calebstewart/bypass-clm
        $string11 = /calebstewart\/bypass\-clm/ nocase ascii wide

    condition:
        any of them
}
