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
        $string1 = /\sClone_Token\s\/Process\:.{0,1000}\s\/Command\:/ nocase ascii wide
        // Description: A tool to elevate privilege with Windows Tokens
        // Reference: https://github.com/0xbadjuju/Tokenvator
        $string2 = /\ssteal_token\s\/process\:.{0,1000}\s\/command\:/ nocase ascii wide
        // Description: A tool to elevate privilege with Windows Tokens
        // Reference: https://github.com/0xbadjuju/Tokenvator
        $string3 = /\stokenvator\s/ nocase ascii wide
        // Description: A tool to elevate privilege with Windows Tokens
        // Reference: https://github.com/0xbadjuju/Tokenvator
        $string4 = /\/MonkeyWorks\.git/ nocase ascii wide
        // Description: A tool to elevate privilege with Windows Tokens
        // Reference: https://github.com/0xbadjuju/Tokenvator
        $string5 = /\/ServiceName\:TokenDriver/ nocase ascii wide
        // Description: A tool to elevate privilege with Windows Tokens
        // Reference: https://github.com/0xbadjuju/Tokenvator
        $string6 = /\/Tokenvator\// nocase ascii wide
        // Description: A tool to elevate privilege with Windows Tokens
        // Reference: https://github.com/0xbadjuju/Tokenvator
        $string7 = /\\KernelTokens\.sys/ nocase ascii wide
        // Description: A tool to elevate privilege with Windows Tokens
        // Reference: https://github.com/0xbadjuju/Tokenvator
        $string8 = /\\Tokenvator\\/ nocase ascii wide
        // Description: A tool to elevate privilege with Windows Tokens
        // Reference: https://github.com/0xbadjuju/Tokenvator
        $string9 = /0xbadjuju\/Tokenvator/ nocase ascii wide
        // Description: A tool to elevate privilege with Windows Tokens
        // Reference: https://github.com/0xbadjuju/Tokenvator
        $string10 = /Add_Privilege\s\/Process\:.{0,1000}\s\/Privilege\:/ nocase ascii wide
        // Description: A tool to elevate privilege with Windows Tokens
        // Reference: https://github.com/0xbadjuju/Tokenvator
        $string11 = /BypassUAC\s.{0,1000}\.exe/ nocase ascii wide
        // Description: A tool to elevate privilege with Windows Tokens
        // Reference: https://github.com/0xbadjuju/Tokenvator
        $string12 = /Disable_Privilege\s\/Process\:.{0,1000}\s\/Privilege\:/ nocase ascii wide
        // Description: A tool to elevate privilege with Windows Tokens
        // Reference: https://github.com/0xbadjuju/Tokenvator
        $string13 = /Enable_Privilege\s\/Process\:.{0,1000}\s\/Privilege\:/ nocase ascii wide
        // Description: A tool to elevate privilege with Windows Tokens
        // Reference: https://github.com/0xbadjuju/Tokenvator
        $string14 = /Enumeration\/DesktopACL/ nocase ascii wide
        // Description: A tool to elevate privilege with Windows Tokens
        // Reference: https://github.com/0xbadjuju/Tokenvator
        $string15 = /Enumeration\\DesktopAC/ nocase ascii wide
        // Description: A tool to elevate privilege with Windows Tokens
        // Reference: https://github.com/0xbadjuju/Tokenvator
        $string16 = /List_Privileges\s\/Process\:powershell/ nocase ascii wide
        // Description: A tool to elevate privilege with Windows Tokens
        // Reference: https://github.com/0xbadjuju/Tokenvator
        $string17 = /Nuke_Privileges\s\/Process\:/ nocase ascii wide
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
        $string21 = /Remove_Privilege\s\/Process\:.{0,1000}\s\/Privilege\:/ nocase ascii wide
        // Description: A tool to elevate privilege with Windows Tokens
        // Reference: https://github.com/0xbadjuju/Tokenvator
        $string22 = /Steal_Pipe_Token\s\/PipeName/ nocase ascii wide
        // Description: A tool to alter privilege with Windows Tokens
        // Reference: https://github.com/0xbadjuju/Tokenvator
        $string23 = /Tokenvator/ nocase ascii wide
        // Description: A tool to elevate privilege with Windows Tokens
        // Reference: https://github.com/0xbadjuju/Tokenvator
        $string24 = /Tokenvator.{0,1000}\.exe/ nocase ascii wide
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
        $string32 = /Tokenvator\/MonkeyWorks/ nocase ascii wide

    condition:
        any of them
}
