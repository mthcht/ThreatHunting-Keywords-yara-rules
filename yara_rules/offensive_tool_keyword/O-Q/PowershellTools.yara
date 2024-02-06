rule PowershellTools
{
    meta:
        description = "Detection patterns for the tool 'PowershellTools' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PowershellTools"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Powershell tools used for Red Team / Pentesting
        // Reference: https://github.com/gustanini/PowershellTools
        $string1 = /\sPowerTools\.ps1/ nocase ascii wide
        // Description: Powershell tools used for Red Team / Pentesting
        // Reference: https://github.com/gustanini/PowershellTools
        $string2 = /\sQuickViewAD\.ps1/ nocase ascii wide
        // Description: Powershell tools used for Red Team / Pentesting
        // Reference: https://github.com/gustanini/PowershellTools
        $string3 = /\.exe\sasktgs\s\/ticket\:B64_TGT\s\/service\:/ nocase ascii wide
        // Description: Powershell tools used for Red Team / Pentesting
        // Reference: https://github.com/gustanini/PowershellTools
        $string4 = /\.exe\ssilver\s\/sids\:.{0,1000}\/target\:/ nocase ascii wide
        // Description: Powershell tools used for Red Team / Pentesting
        // Reference: https://github.com/gustanini/PowershellTools
        $string5 = /\/PowershellTools\.git/ nocase ascii wide
        // Description: Powershell tools used for Red Team / Pentesting
        // Reference: https://github.com/gustanini/PowershellTools
        $string6 = /\/PowerTools\.ps1/ nocase ascii wide
        // Description: Powershell tools used for Red Team / Pentesting
        // Reference: https://github.com/gustanini/PowershellTools
        $string7 = /\/QuickViewAD\.ps1/ nocase ascii wide
        // Description: Powershell tools used for Red Team / Pentesting
        // Reference: https://github.com/gustanini/PowershellTools
        $string8 = /\\PowerTools\.ps1/ nocase ascii wide
        // Description: Powershell tools used for Red Team / Pentesting
        // Reference: https://github.com/gustanini/PowershellTools
        $string9 = /\\QuickViewAD\.ps1/ nocase ascii wide
        // Description: Powershell tools used for Red Team / Pentesting
        // Reference: https://github.com/gustanini/PowershellTools
        $string10 = /C\:\\Temp\\.{0,1000}\-.{0,1000}\.kirbi/ nocase ascii wide
        // Description: Powershell tools used for Red Team / Pentesting
        // Reference: https://github.com/gustanini/PowershellTools
        $string11 = /Find\-ADInterestingACL\s/ nocase ascii wide
        // Description: Powershell tools used for Red Team / Pentesting
        // Reference: https://github.com/gustanini/PowershellTools
        $string12 = /Find\-ADInterestingACL\.ps1/ nocase ascii wide
        // Description: Powershell tools used for Red Team / Pentesting
        // Reference: https://github.com/gustanini/PowershellTools
        $string13 = /Get\-NestedGroupMembership\s/ nocase ascii wide
        // Description: Powershell tools used for Red Team / Pentesting
        // Reference: https://github.com/gustanini/PowershellTools
        $string14 = /Get\-NestedGroupMembership\.ps1/ nocase ascii wide
        // Description: Powershell tools used for Red Team / Pentesting
        // Reference: https://github.com/gustanini/PowershellTools
        $string15 = /Get\-TrustTicket\.ps1/ nocase ascii wide
        // Description: Powershell tools used for Red Team / Pentesting
        // Reference: https://github.com/gustanini/PowershellTools
        $string16 = /gustanini\/PowershellTools/ nocase ascii wide
        // Description: Powershell tools used for Red Team / Pentesting
        // Reference: https://github.com/gustanini/PowershellTools
        $string17 = /Invoke\-AccessCheck\s\-PSRemoting/ nocase ascii wide
        // Description: Powershell tools used for Red Team / Pentesting
        // Reference: https://github.com/gustanini/PowershellTools
        $string18 = /Invoke\-AccessCheck\s\-SMB/ nocase ascii wide
        // Description: Powershell tools used for Red Team / Pentesting
        // Reference: https://github.com/gustanini/PowershellTools
        $string19 = /Invoke\-AccessCheck\.ps1/ nocase ascii wide
        // Description: Powershell tools used for Red Team / Pentesting
        // Reference: https://github.com/gustanini/PowershellTools
        $string20 = /kerberos\:\:golden\s\/service\:/ nocase ascii wide
        // Description: Powershell tools used for Red Team / Pentesting
        // Reference: https://github.com/gustanini/PowershellTools
        $string21 = /PowershellTools\-main\.zip/ nocase ascii wide
        // Description: Powershell tools used for Red Team / Pentesting
        // Reference: https://github.com/gustanini/PowershellTools
        $string22 = /Set\-MacroSecurityOff\s/ nocase ascii wide
        // Description: Powershell tools used for Red Team / Pentesting
        // Reference: https://github.com/gustanini/PowershellTools
        $string23 = /Set\-MacroSecurityOff\.ps1/ nocase ascii wide
        // Description: Powershell tools used for Red Team / Pentesting
        // Reference: https://github.com/gustanini/PowershellTools
        $string24 = /tgs\:\:ask\s\/tgt\:/ nocase ascii wide

    condition:
        any of them
}
