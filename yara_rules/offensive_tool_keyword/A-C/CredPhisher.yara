rule CredPhisher
{
    meta:
        description = "Detection patterns for the tool 'CredPhisher' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "CredPhisher"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Prompts the current user for their credentials using the CredUIPromptForWindowsCredentials WinAPI function
        // Reference: https://github.com/matterpreter/OffensiveCSharp/tree/master/CredPhisher
        $string1 = /\/CredPhisher\// nocase ascii wide
        // Description: Prompts the current user for their credentials using the CredUIPromptForWindowsCredentials WinAPI function
        // Reference: https://github.com/matterpreter/OffensiveCSharp/tree/master/CredPhisher
        $string2 = /CredPhisher\.csproj/ nocase ascii wide
        // Description: Prompts the current user for their credentials using the CredUIPromptForWindowsCredentials WinAPI function
        // Reference: https://github.com/matterpreter/OffensiveCSharp/tree/master/CredPhisher
        $string3 = /CredPhisher\.exe/ nocase ascii wide
        // Description: Prompts the current user for their credentials using the CredUIPromptForWindowsCredentials WinAPI function
        // Reference: https://github.com/matterpreter/OffensiveCSharp/tree/master/CredPhisher
        $string4 = /namespace\sCredPhisher/ nocase ascii wide

    condition:
        any of them
}
