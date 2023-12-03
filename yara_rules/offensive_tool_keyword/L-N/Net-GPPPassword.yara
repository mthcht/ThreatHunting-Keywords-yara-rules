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
        $string1 = /.{0,1000}\/Net\-GPPPassword\.git.{0,1000}/ nocase ascii wide
        // Description: .NET implementation of Get-GPPPassword. Retrieves the plaintext password and other information for accounts pushed through Group Policy Preferences.
        // Reference: https://github.com/outflanknl/Net-GPPPassword
        $string2 = /.{0,1000}Net\-GPPPassword\.cs.{0,1000}/ nocase ascii wide
        // Description: .NET implementation of Get-GPPPassword. Retrieves the plaintext password and other information for accounts pushed through Group Policy Preferences.
        // Reference: https://github.com/outflanknl/Net-GPPPassword
        $string3 = /.{0,1000}Net\-GPPPassword\.exe.{0,1000}/ nocase ascii wide
        // Description: .NET implementation of Get-GPPPassword. Retrieves the plaintext password and other information for accounts pushed through Group Policy Preferences.
        // Reference: https://github.com/outflanknl/Net-GPPPassword
        $string4 = /.{0,1000}Net\-GPPPassword_dotNET.{0,1000}/ nocase ascii wide
        // Description: .NET implementation of Get-GPPPassword. Retrieves the plaintext password and other information for accounts pushed through Group Policy Preferences.
        // Reference: https://github.com/outflanknl/Net-GPPPassword
        $string5 = /.{0,1000}Net\-GPPPassword\-master.{0,1000}/ nocase ascii wide
        // Description: .NET implementation of Get-GPPPassword. Retrieves the plaintext password and other information for accounts pushed through Group Policy Preferences.
        // Reference: https://github.com/outflanknl/Net-GPPPassword
        $string6 = /.{0,1000}outflanknl\/Net\-GPPPassword.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
