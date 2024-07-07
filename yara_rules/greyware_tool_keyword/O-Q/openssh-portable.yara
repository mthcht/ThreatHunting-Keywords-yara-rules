rule openssh_portable
{
    meta:
        description = "Detection patterns for the tool 'openssh-portable' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "openssh-portable"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: monitoring openssh usage
        // Reference: https://github.com/PowerShell/openssh-portable
        $string1 = /\\\\pipe\\\\openssh\-ssh\-agent/ nocase ascii wide
        // Description: monitoring openssh usage
        // Reference: https://github.com/PowerShell/openssh-portable
        $string2 = /\\OpenSSHTestTasks\\/ nocase ascii wide
        // Description: monitoring openssh usage
        // Reference: https://github.com/PowerShell/openssh-portable
        $string3 = /\\pipe\\openssh\-ssh\-agent/ nocase ascii wide
        // Description: monitoring openssh usage
        // Reference: https://github.com/PowerShell/openssh-portable
        $string4 = /\\Software\\OpenSSH\\DefaultShell/ nocase ascii wide
        // Description: monitoring openssh usage
        // Reference: https://github.com/PowerShell/openssh-portable
        $string5 = /install\-sshd\.ps1/ nocase ascii wide
        // Description: monitoring openssh usage
        // Reference: https://github.com/PowerShell/openssh-portable
        $string6 = /net\sstart\sssh\-agent/ nocase ascii wide
        // Description: monitoring openssh usage
        // Reference: https://github.com/PowerShell/openssh-portable
        $string7 = /New\-Service\s\-Name\ssshd/ nocase ascii wide

    condition:
        any of them
}
