rule adaudit
{
    meta:
        description = "Detection patterns for the tool 'adaudit' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "adaudit"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Powershell script to do domain auditing automation
        // Reference: https://github.com/phillips321/adaudit
        $string1 = /\sadaudit\.ps1/ nocase ascii wide
        // Description: Powershell script to do domain auditing automation
        // Reference: https://github.com/phillips321/adaudit
        $string2 = /\/adaudit\.git/ nocase ascii wide
        // Description: Powershell script to do domain auditing automation
        // Reference: https://github.com/phillips321/adaudit
        $string3 = /\/adaudit\.ps1/ nocase ascii wide
        // Description: Powershell script to do domain auditing automation
        // Reference: https://github.com/phillips321/adaudit
        $string4 = /\[\!\]\sAS\-REP\sRoastable\suser\:/ nocase ascii wide
        // Description: Powershell script to do domain auditing automation
        // Reference: https://github.com/phillips321/adaudit
        $string5 = /\[\+\]\sNTDS\.dit\,\sSYSTEM\s\&\sSAM\ssaved\sto\soutput\sfolder/ nocase ascii wide
        // Description: Powershell script to do domain auditing automation
        // Reference: https://github.com/phillips321/adaudit
        $string6 = /\[\+\]\sUse\ssecretsdump\.py/ nocase ascii wide
        // Description: Powershell script to do domain auditing automation
        // Reference: https://github.com/phillips321/adaudit
        $string7 = /\\adaudit\.ps1/ nocase ascii wide
        // Description: Powershell script to do domain auditing automation
        // Reference: https://github.com/phillips321/adaudit
        $string8 = "54709655b001aa4d02b8040574970decd2e185a1ca4effbf87eb94574b9c87a0" nocase ascii wide
        // Description: Powershell script to do domain auditing automation
        // Reference: https://github.com/phillips321/adaudit
        $string9 = "Find-DangerousACLPermissions" nocase ascii wide
        // Description: Powershell script to do domain auditing automation
        // Reference: https://github.com/phillips321/adaudit
        $string10 = "Get-ADUsersWithoutPreAuth" nocase ascii wide
        // Description: Powershell script to do domain auditing automation
        // Reference: https://github.com/phillips321/adaudit
        $string11 = "phillips321/adaudit" nocase ascii wide
        // Description: Powershell script to do domain auditing automation
        // Reference: https://github.com/phillips321/adaudit
        $string12 = "Search-ADAccount -PasswordNeverExpires -UsersOnly" nocase ascii wide
        // Description: Powershell script to do domain auditing automation
        // Reference: https://github.com/phillips321/adaudit
        $string13 = /Write\-Nessus\-Finding\(/ nocase ascii wide

    condition:
        any of them
}
