rule Openssh
{
    meta:
        description = "Detection patterns for the tool 'Openssh' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Openssh"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Install OpenSSH Server service on windows - abused by attacker for persistant control
        // Reference: https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh_install_firstuse?tabs=powershell#install-openssh-for-windows
        $string1 = /Add\-WindowsCapability\s\-Online\s\-Name\sOpenSSH\.Server/ nocase ascii wide
        // Description: monitoring openssh usage
        // Reference: https://github.com/PowerShell/openssh-portable
        $string2 = /Import\-Module\s.{0,1000}\\OpenSSHUtils/ nocase ascii wide

    condition:
        any of them
}
