rule unicorn
{
    meta:
        description = "Detection patterns for the tool 'unicorn' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "unicorn"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Unicorn is a simple tool for using a PowerShell downgrade attack and inject shellcode straight into memory
        // Reference: https://github.com/trustedsec/unicorn
        $string1 = /.{0,1000}\sunicorn\.py.{0,1000}/ nocase ascii wide
        // Description: Unicorn is a simple tool for using a PowerShell downgrade attack and inject shellcode straight into memory
        // Reference: https://github.com/trustedsec/unicorn
        $string2 = /.{0,1000}\.py\s.{0,1000}\.cs\scs\sms.{0,1000}/ nocase ascii wide
        // Description: Unicorn is a simple tool for using a PowerShell downgrade attack and inject shellcode straight into memory
        // Reference: https://github.com/trustedsec/unicorn
        $string3 = /.{0,1000}\.txt\sshellcode\shta.{0,1000}/ nocase ascii wide
        // Description: Unicorn is a simple tool for using a PowerShell downgrade attack and inject shellcode straight into memory
        // Reference: https://github.com/trustedsec/unicorn
        $string4 = /.{0,1000}\.txt\sshellcode\smacro.{0,1000}/ nocase ascii wide
        // Description: Unicorn is a simple tool for using a PowerShell downgrade attack and inject shellcode straight into memory
        // Reference: https://github.com/trustedsec/unicorn
        $string5 = /.{0,1000}\.txt\sshellcode\sms.{0,1000}/ nocase ascii wide
        // Description: Unicorn is a simple tool for using a PowerShell downgrade attack and inject shellcode straight into memory
        // Reference: https://github.com/trustedsec/unicorn
        $string6 = /.{0,1000}\/unicorn\.git.{0,1000}/ nocase ascii wide
        // Description: Unicorn is a simple tool for using a PowerShell downgrade attack and inject shellcode straight into memory
        // Reference: https://github.com/trustedsec/unicorn
        $string7 = /.{0,1000}\/unicorn\.py.{0,1000}/ nocase ascii wide
        // Description: Unicorn is a simple tool for using a PowerShell downgrade attack and inject shellcode straight into memory
        // Reference: https://github.com/trustedsec/unicorn
        $string8 = /.{0,1000}ASBBypass\.ps1.{0,1000}/ nocase ascii wide
        // Description: Unicorn is a simple tool for using a PowerShell downgrade attack and inject shellcode straight into memory
        // Reference: https://github.com/trustedsec/unicorn
        $string9 = /.{0,1000}trustedsec\/unicorn.{0,1000}/ nocase ascii wide
        // Description: Unicorn is a simple tool for using a PowerShell downgrade attack and inject shellcode straight into memory
        // Reference: https://github.com/trustedsec/unicorn
        $string10 = /.{0,1000}unicorn\.py\s.{0,1000}/ nocase ascii wide
        // Description: Unicorn is a simple tool for using a PowerShell downgrade attack and inject shellcode straight into memory
        // Reference: https://github.com/trustedsec/unicorn
        $string11 = /.{0,1000}unicorn\-master\.zip.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
