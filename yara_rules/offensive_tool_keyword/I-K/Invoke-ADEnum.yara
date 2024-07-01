rule Invoke_ADEnum
{
    meta:
        description = "Detection patterns for the tool 'Invoke-ADEnum' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Invoke-ADEnum"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Automate Active Directory Enumeration
        // Reference: https://github.com/Leo4j/Invoke-ADEnum
        $string1 = /\s\-Recommended\s\-SprayEmptyPasswords/ nocase ascii wide
        // Description: Automate Active Directory Enumeration
        // Reference: https://github.com/Leo4j/Invoke-ADEnum
        $string2 = /\$EmptyPasswordUsers/ nocase ascii wide
        // Description: Automate Active Directory Enumeration
        // Reference: https://github.com/Leo4j/Invoke-ADEnum
        $string3 = /\$PotentialComputersWithEmptyPassword/ nocase ascii wide
        // Description: Automate Active Directory Enumeration
        // Reference: https://github.com/Leo4j/Invoke-ADEnum
        $string4 = /\$PotentialUsersWithEmptyPassword/ nocase ascii wide
        // Description: Automate Active Directory Enumeration
        // Reference: https://github.com/Leo4j/Invoke-ADEnum
        $string5 = /\$SprayEmptyPasswords/ nocase ascii wide
        // Description: Automate Active Directory Enumeration
        // Reference: https://github.com/Leo4j/Invoke-ADEnum
        $string6 = /\/Invoke\-ADEnum\.git/ nocase ascii wide
        // Description: Automate Active Directory Enumeration
        // Reference: https://github.com/Leo4j/Invoke-ADEnum
        $string7 = /\\.{0,1000}_AD\-Audit_.{0,1000}\.txt/ nocase ascii wide
        // Description: Automate Active Directory Enumeration
        // Reference: https://github.com/Leo4j/Invoke-ADEnum
        $string8 = /\\Invoke\-ADEnum\\/ nocase ascii wide
        // Description: Automate Active Directory Enumeration
        // Reference: https://github.com/Leo4j/Invoke-ADEnum
        $string9 = /\\Invoke\-ADEnum\-main/ nocase ascii wide
        // Description: Automate Active Directory Enumeration
        // Reference: https://github.com/Leo4j/Invoke-ADEnum
        $string10 = /\\krbtgtAccounts\.json/ nocase ascii wide
        // Description: Automate Active Directory Enumeration
        // Reference: https://github.com/Leo4j/Invoke-ADEnum
        $string11 = /\]\sCollecting\sKrbtgt/ nocase ascii wide
        // Description: Automate Active Directory Enumeration
        // Reference: https://github.com/Leo4j/Invoke-ADEnum
        $string12 = /27049d9f4a7125e9be92e84edcad5dc118bc8503920fb3250b3e2f7577370b49/ nocase ascii wide
        // Description: Automate Active Directory Enumeration
        // Reference: https://github.com/Leo4j/Invoke-ADEnum
        $string13 = /Find\-LocalAdminAccess\s/ nocase ascii wide
        // Description: Automate Active Directory Enumeration
        // Reference: https://github.com/Leo4j/Invoke-ADEnum
        $string14 = /Invoke\-ADEnum\s\-/ nocase ascii wide
        // Description: Automate Active Directory Enumeration
        // Reference: https://github.com/Leo4j/Invoke-ADEnum
        $string15 = /Invoke\-ADEnum\.ps1/ nocase ascii wide
        // Description: Automate Active Directory Enumeration
        // Reference: https://github.com/Leo4j/Invoke-ADEnum
        $string16 = /Invoke\-ShareHunter\s/ nocase ascii wide
        // Description: Automate Active Directory Enumeration
        // Reference: https://github.com/Leo4j/Invoke-ADEnum
        $string17 = /Leo4j\/Invoke\-ADEnum/ nocase ascii wide

    condition:
        any of them
}
