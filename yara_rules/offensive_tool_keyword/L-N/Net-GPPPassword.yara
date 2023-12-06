rule Net_GPPPassword
{
    meta:
        description = "Detection patterns for the tool 'Net-GPPPassword' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Net-GPPPassword"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: .NET implementation of Get-GPPPassword. Retrieves the plaintext password and other information for accounts pushed through Group Policy Preferences.
        // Reference: https://github.com/outflanknl/Net-GPPPassword
        $string1 = /\/Net\-GPPPassword\.git/ nocase ascii wide
        // Description: .NET implementation of Get-GPPPassword. Retrieves the plaintext password and other information for accounts pushed through Group Policy Preferences.
        // Reference: https://github.com/outflanknl/Net-GPPPassword
        $string2 = /Net\-GPPPassword\.cs/ nocase ascii wide
        // Description: .NET implementation of Get-GPPPassword. Retrieves the plaintext password and other information for accounts pushed through Group Policy Preferences.
        // Reference: https://github.com/outflanknl/Net-GPPPassword
        $string3 = /Net\-GPPPassword\.exe/ nocase ascii wide
        // Description: .NET implementation of Get-GPPPassword. Retrieves the plaintext password and other information for accounts pushed through Group Policy Preferences.
        // Reference: https://github.com/outflanknl/Net-GPPPassword
        $string4 = /Net\-GPPPassword_dotNET/ nocase ascii wide
        // Description: .NET implementation of Get-GPPPassword. Retrieves the plaintext password and other information for accounts pushed through Group Policy Preferences.
        // Reference: https://github.com/outflanknl/Net-GPPPassword
        $string5 = /Net\-GPPPassword\-master/ nocase ascii wide
        // Description: .NET implementation of Get-GPPPassword. Retrieves the plaintext password and other information for accounts pushed through Group Policy Preferences.
        // Reference: https://github.com/outflanknl/Net-GPPPassword
        $string6 = /outflanknl\/Net\-GPPPassword/ nocase ascii wide

    condition:
        any of them
}
