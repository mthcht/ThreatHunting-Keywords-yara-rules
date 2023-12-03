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
        $string1 = /.{0,1000}\sClone_Token\s\/Process:.{0,1000}\s\/Command:.{0,1000}/ nocase ascii wide
        // Description: A tool to elevate privilege with Windows Tokens
        // Reference: https://github.com/0xbadjuju/Tokenvator
        $string2 = /.{0,1000}\ssteal_token\s\/process:.{0,1000}\s\/command:.{0,1000}/ nocase ascii wide
        // Description: A tool to elevate privilege with Windows Tokens
        // Reference: https://github.com/0xbadjuju/Tokenvator
        $string3 = /.{0,1000}\stokenvator\s.{0,1000}/ nocase ascii wide
        // Description: A tool to elevate privilege with Windows Tokens
        // Reference: https://github.com/0xbadjuju/Tokenvator
        $string4 = /.{0,1000}\/MonkeyWorks\.git.{0,1000}/ nocase ascii wide
        // Description: A tool to elevate privilege with Windows Tokens
        // Reference: https://github.com/0xbadjuju/Tokenvator
        $string5 = /.{0,1000}\/ServiceName:TokenDriver.{0,1000}/ nocase ascii wide
        // Description: A tool to elevate privilege with Windows Tokens
        // Reference: https://github.com/0xbadjuju/Tokenvator
        $string6 = /.{0,1000}\/Tokenvator\/.{0,1000}/ nocase ascii wide
        // Description: A tool to elevate privilege with Windows Tokens
        // Reference: https://github.com/0xbadjuju/Tokenvator
        $string7 = /.{0,1000}\\KernelTokens\.sys.{0,1000}/ nocase ascii wide
        // Description: A tool to elevate privilege with Windows Tokens
        // Reference: https://github.com/0xbadjuju/Tokenvator
        $string8 = /.{0,1000}\\Tokenvator\\.{0,1000}/ nocase ascii wide
        // Description: A tool to elevate privilege with Windows Tokens
        // Reference: https://github.com/0xbadjuju/Tokenvator
        $string9 = /.{0,1000}0xbadjuju\/Tokenvator.{0,1000}/ nocase ascii wide
        // Description: A tool to elevate privilege with Windows Tokens
        // Reference: https://github.com/0xbadjuju/Tokenvator
        $string10 = /.{0,1000}Add_Privilege\s\/Process:.{0,1000}\s\/Privilege:.{0,1000}/ nocase ascii wide
        // Description: A tool to elevate privilege with Windows Tokens
        // Reference: https://github.com/0xbadjuju/Tokenvator
        $string11 = /.{0,1000}BypassUAC\s.{0,1000}\.exe.{0,1000}/ nocase ascii wide
        // Description: A tool to elevate privilege with Windows Tokens
        // Reference: https://github.com/0xbadjuju/Tokenvator
        $string12 = /.{0,1000}Disable_Privilege\s\/Process:.{0,1000}\s\/Privilege:.{0,1000}/ nocase ascii wide
        // Description: A tool to elevate privilege with Windows Tokens
        // Reference: https://github.com/0xbadjuju/Tokenvator
        $string13 = /.{0,1000}Enable_Privilege\s\/Process:.{0,1000}\s\/Privilege:.{0,1000}/ nocase ascii wide
        // Description: A tool to elevate privilege with Windows Tokens
        // Reference: https://github.com/0xbadjuju/Tokenvator
        $string14 = /.{0,1000}Enumeration\/DesktopACL.{0,1000}/ nocase ascii wide
        // Description: A tool to elevate privilege with Windows Tokens
        // Reference: https://github.com/0xbadjuju/Tokenvator
        $string15 = /.{0,1000}Enumeration\\DesktopAC.{0,1000}/ nocase ascii wide
        // Description: A tool to elevate privilege with Windows Tokens
        // Reference: https://github.com/0xbadjuju/Tokenvator
        $string16 = /.{0,1000}List_Privileges\s\/Process:powershell.{0,1000}/ nocase ascii wide
        // Description: A tool to elevate privilege with Windows Tokens
        // Reference: https://github.com/0xbadjuju/Tokenvator
        $string17 = /.{0,1000}Nuke_Privileges\s\/Process:.{0,1000}/ nocase ascii wide
        // Description: A tool to elevate privilege with Windows Tokens
        // Reference: https://github.com/0xbadjuju/Tokenvator
        $string18 = /.{0,1000}Plugins\\AccessTokens\\TokenDriver.{0,1000}/ nocase ascii wide
        // Description: A tool to elevate privilege with Windows Tokens
        // Reference: https://github.com/0xbadjuju/Tokenvator
        $string19 = /.{0,1000}Plugins\\AccessTokens\\TokenManipulation.{0,1000}/ nocase ascii wide
        // Description: A tool to elevate privilege with Windows Tokens
        // Reference: https://github.com/0xbadjuju/Tokenvator
        $string20 = /.{0,1000}Plugins\\Execution\\PSExec.{0,1000}/ nocase ascii wide
        // Description: A tool to elevate privilege with Windows Tokens
        // Reference: https://github.com/0xbadjuju/Tokenvator
        $string21 = /.{0,1000}Remove_Privilege\s\/Process:.{0,1000}\s\/Privilege:.{0,1000}/ nocase ascii wide
        // Description: A tool to elevate privilege with Windows Tokens
        // Reference: https://github.com/0xbadjuju/Tokenvator
        $string22 = /.{0,1000}Steal_Pipe_Token\s\/PipeName.{0,1000}/ nocase ascii wide
        // Description: A tool to alter privilege with Windows Tokens
        // Reference: https://github.com/0xbadjuju/Tokenvator
        $string23 = /.{0,1000}Tokenvator.{0,1000}/ nocase ascii wide
        // Description: A tool to elevate privilege with Windows Tokens
        // Reference: https://github.com/0xbadjuju/Tokenvator
        $string24 = /.{0,1000}Tokenvator.{0,1000}\.exe.{0,1000}/ nocase ascii wide
        // Description: A tool to elevate privilege with Windows Tokens
        // Reference: https://github.com/0xbadjuju/Tokenvator
        $string25 = /.{0,1000}Tokenvator\.csproj.{0,1000}/ nocase ascii wide
        // Description: A tool to elevate privilege with Windows Tokens
        // Reference: https://github.com/0xbadjuju/Tokenvator
        $string26 = /.{0,1000}Tokenvator\.exe.{0,1000}/ nocase ascii wide
        // Description: A tool to elevate privilege with Windows Tokens
        // Reference: https://github.com/0xbadjuju/Tokenvator
        $string27 = /.{0,1000}Tokenvator\.git.{0,1000}/ nocase ascii wide
        // Description: A tool to elevate privilege with Windows Tokens
        // Reference: https://github.com/0xbadjuju/Tokenvator
        $string28 = /.{0,1000}Tokenvator\.pdb.{0,1000}/ nocase ascii wide
        // Description: A tool to elevate privilege with Windows Tokens
        // Reference: https://github.com/0xbadjuju/Tokenvator
        $string29 = /.{0,1000}Tokenvator\.Plugins.{0,1000}/ nocase ascii wide
        // Description: A tool to elevate privilege with Windows Tokens
        // Reference: https://github.com/0xbadjuju/Tokenvator
        $string30 = /.{0,1000}Tokenvator\.Resources.{0,1000}/ nocase ascii wide
        // Description: A tool to elevate privilege with Windows Tokens
        // Reference: https://github.com/0xbadjuju/Tokenvator
        $string31 = /.{0,1000}Tokenvator\.sln.{0,1000}/ nocase ascii wide
        // Description: A tool to elevate privilege with Windows Tokens
        // Reference: https://github.com/0xbadjuju/Tokenvator
        $string32 = /.{0,1000}Tokenvator\/MonkeyWorks.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
