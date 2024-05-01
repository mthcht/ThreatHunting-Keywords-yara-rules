rule wmiexec_pro
{
    meta:
        description = "Detection patterns for the tool 'wmiexec-pro' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "wmiexec-pro"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: The new generation of wmiexec.py with new features whole the operations only work with port 135 (don't need smb connection) for AV evasion in Lateral Movement
        // Reference: https://github.com/XiaoliChan/wmiexec-Pro
        $string1 = /\sexec\-command\s\-clear/ nocase ascii wide
        // Description: The new generation of wmiexec.py with new features whole the operations only work with port 135 (don't need smb connection) for AV evasion in Lateral Movement
        // Reference: https://github.com/XiaoliChan/wmiexec-Pro
        $string2 = /\sexec\-command\s\-command\s/ nocase ascii wide
        // Description: The new generation of wmiexec.py with new features whole the operations only work with port 135 (don't need smb connection) for AV evasion in Lateral Movement
        // Reference: https://github.com/XiaoliChan/wmiexec-Pro
        $string3 = /\sexec\-command\s\-shell/ nocase ascii wide
        // Description: The new generation of wmiexec.py with new features whole the operations only work with port 135 (don't need smb connection) for AV evasion in Lateral Movement
        // Reference: https://github.com/XiaoliChan/wmiexec-Pro
        $string4 = /\sfiletransfer\s\-download\s\-src\-file\s.{0,1000}\.exe.{0,1000}\/tmp/ nocase ascii wide
        // Description: The new generation of wmiexec.py with new features whole the operations only work with port 135 (don't need smb connection) for AV evasion in Lateral Movement
        // Reference: https://github.com/XiaoliChan/wmiexec-Pro
        $string5 = /\sfiletransfer\s\-upload\s\-src\-file\s.{0,1000}\.exe.{0,1000}\\temp/ nocase ascii wide
        // Description: The new generation of wmiexec.py with new features whole the operations only work with port 135 (don't need smb connection) for AV evasion in Lateral Movement
        // Reference: https://github.com/XiaoliChan/wmiexec-Pro
        $string6 = /\s\-no\-pass\srid\-hijack/ nocase ascii wide
        // Description: The new generation of wmiexec.py with new features whole the operations only work with port 135 (don't need smb connection) for AV evasion in Lateral Movement
        // Reference: https://github.com/XiaoliChan/wmiexec-Pro
        $string7 = /\srid\-hijack\s\-/ nocase ascii wide
        // Description: The new generation of wmiexec.py with new features whole the operations only work with port 135 (don't need smb connection) for AV evasion in Lateral Movement
        // Reference: https://github.com/XiaoliChan/wmiexec-Pro
        $string8 = /\sservice\s\-dump\sall\-services\.json/ nocase ascii wide
        // Description: The new generation of wmiexec.py with new features whole the operations only work with port 135 (don't need smb connection) for AV evasion in Lateral Movement
        // Reference: https://github.com/XiaoliChan/wmiexec-Pro
        $string9 = /\.py\s.{0,1000}\samsi\s\-disable/ nocase ascii wide
        // Description: The new generation of wmiexec.py with new features whole the operations only work with port 135 (don't need smb connection) for AV evasion in Lateral Movement
        // Reference: https://github.com/XiaoliChan/wmiexec-Pro
        $string10 = /\.py\s.{0,1000}\samsi\s\-enable/ nocase ascii wide
        // Description: The new generation of wmiexec.py with new features whole the operations only work with port 135 (don't need smb connection) for AV evasion in Lateral Movement
        // Reference: https://github.com/XiaoliChan/wmiexec-Pro
        $string11 = /\.py.{0,1000}\sservice\s\-action\screate\s\-service\-name\s/ nocase ascii wide
        // Description: The new generation of wmiexec.py with new features whole the operations only work with port 135 (don't need smb connection) for AV evasion in Lateral Movement
        // Reference: https://github.com/XiaoliChan/wmiexec-Pro
        $string12 = /\/wmiexec\-Pro/ nocase ascii wide
        // Description: The new generation of wmiexec.py with new features whole the operations only work with port 135 (don't need smb connection) for AV evasion in Lateral Movement
        // Reference: https://github.com/XiaoliChan/wmiexec-Pro
        $string13 = /\/wmiexec\-Pro\.git/ nocase ascii wide
        // Description: The new generation of wmiexec.py with new features whole the operations only work with port 135 (don't need smb connection) for AV evasion in Lateral Movement
        // Reference: https://github.com/XiaoliChan/wmiexec-Pro
        $string14 = /\[\+\]\sAMSI\sBypassed\!/ nocase ascii wide
        // Description: The new generation of wmiexec.py with new features whole the operations only work with port 135 (don't need smb connection) for AV evasion in Lateral Movement
        // Reference: https://github.com/XiaoliChan/wmiexec-Pro
        $string15 = /\[\+\]\sCreate\sevil\sclass\sfor\sfile\stransfer/ nocase ascii wide
        // Description: The new generation of wmiexec.py with new features whole the operations only work with port 135 (don't need smb connection) for AV evasion in Lateral Movement
        // Reference: https://github.com/XiaoliChan/wmiexec-Pro
        $string16 = /\[\+\]\sNuke\sis\slanding\./ nocase ascii wide
        // Description: The new generation of wmiexec.py with new features whole the operations only work with port 135 (don't need smb connection) for AV evasion in Lateral Movement
        // Reference: https://github.com/XiaoliChan/wmiexec-Pro
        $string17 = /\\filetransfer\.py/ nocase ascii wide
        // Description: The new generation of wmiexec.py with new features whole the operations only work with port 135 (don't need smb connection) for AV evasion in Lateral Movement
        // Reference: https://github.com/XiaoliChan/wmiexec-Pro
        $string18 = /\\rid_hijack\.py/ nocase ascii wide
        // Description: The new generation of wmiexec.py with new features whole the operations only work with port 135 (don't need smb connection) for AV evasion in Lateral Movement
        // Reference: https://github.com/XiaoliChan/wmiexec-Pro
        $string19 = /53395d8379dfd716e8708b21490fdec662537be8c56d0df185df59d0ed68eb04/ nocase ascii wide
        // Description: The new generation of wmiexec.py with new features whole the operations only work with port 135 (don't need smb connection) for AV evasion in Lateral Movement
        // Reference: https://github.com/XiaoliChan/wmiexec-Pro
        $string20 = /8bce6c99c0ac4b8d76c49f6e4dece996b77bb7d71d9acdbfcf5b0460811adfb9/ nocase ascii wide
        // Description: The new generation of wmiexec.py with new features whole the operations only work with port 135 (don't need smb connection) for AV evasion in Lateral Movement
        // Reference: https://github.com/XiaoliChan/wmiexec-Pro
        $string21 = /bfe2e4b99edec9921d20bc7f956c1ac48cfc0b08061e23c92ab3461d7cdcf922/ nocase ascii wide
        // Description: The new generation of wmiexec.py with new features whole the operations only work with port 135 (don't need smb connection) for AV evasion in Lateral Movement
        // Reference: https://github.com/XiaoliChan/wmiexec-Pro
        $string22 = /C\:\\aab\.txt/ nocase ascii wide
        // Description: The new generation of wmiexec.py with new features whole the operations only work with port 135 (don't need smb connection) for AV evasion in Lateral Movement
        // Reference: https://github.com/XiaoliChan/wmiexec-Pro
        $string23 = /ClearEventlog\.vbs/ nocase ascii wide
        // Description: The new generation of wmiexec.py with new features whole the operations only work with port 135 (don't need smb connection) for AV evasion in Lateral Movement
        // Reference: https://github.com/XiaoliChan/wmiexec-Pro
        $string24 = /ClearEventlog\.vbs/ nocase ascii wide
        // Description: The new generation of wmiexec.py with new features whole the operations only work with port 135 (don't need smb connection) for AV evasion in Lateral Movement
        // Reference: https://github.com/XiaoliChan/wmiexec-Pro
        $string25 = /e6db508c611d834b9ad9f20bebef8507fec5f642a051ea1c6ae659b729db3c1c/ nocase ascii wide
        // Description: The new generation of wmiexec.py with new features whole the operations only work with port 135 (don't need smb connection) for AV evasion in Lateral Movement
        // Reference: https://github.com/XiaoliChan/wmiexec-Pro
        $string26 = /eventlog\s\-risk\-i\-know/ nocase ascii wide
        // Description: The new generation of wmiexec.py with new features whole the operations only work with port 135 (don't need smb connection) for AV evasion in Lateral Movement
        // Reference: https://github.com/XiaoliChan/wmiexec-Pro
        $string27 = /eventlog_fucker\.py/ nocase ascii wide
        // Description: The new generation of wmiexec.py with new features whole the operations only work with port 135 (don't need smb connection) for AV evasion in Lateral Movement
        // Reference: https://github.com/XiaoliChan/wmiexec-Pro
        $string28 = /eventlog\-fucker\.py/ nocase ascii wide
        // Description: The new generation of wmiexec.py with new features whole the operations only work with port 135 (don't need smb connection) for AV evasion in Lateral Movement
        // Reference: https://github.com/XiaoliChan/wmiexec-Pro
        $string29 = /Exec\-Command\-Silent\.vbs/ nocase ascii wide
        // Description: The new generation of wmiexec.py with new features whole the operations only work with port 135 (don't need smb connection) for AV evasion in Lateral Movement
        // Reference: https://github.com/XiaoliChan/wmiexec-Pro
        $string30 = /Exec\-Command\-Silent\.vbs/ nocase ascii wide
        // Description: The new generation of wmiexec.py with new features whole the operations only work with port 135 (don't need smb connection) for AV evasion in Lateral Movement
        // Reference: https://github.com/XiaoliChan/wmiexec-Pro
        $string31 = /GrantSamAccessPermission\.vbs/ nocase ascii wide
        // Description: The new generation of wmiexec.py with new features whole the operations only work with port 135 (don't need smb connection) for AV evasion in Lateral Movement
        // Reference: https://github.com/XiaoliChan/wmiexec-Pro
        $string32 = /GrantSamAccessPermission\.vbs/ nocase ascii wide
        // Description: The new generation of wmiexec.py with new features whole the operations only work with port 135 (don't need smb connection) for AV evasion in Lateral Movement
        // Reference: https://github.com/XiaoliChan/wmiexec-Pro
        $string33 = /modules\/enumrate\.py/ nocase ascii wide
        // Description: The new generation of wmiexec.py with new features whole the operations only work with port 135 (don't need smb connection) for AV evasion in Lateral Movement
        // Reference: https://github.com/XiaoliChan/wmiexec-Pro
        $string34 = /rid_hijack\.py/ nocase ascii wide
        // Description: The new generation of wmiexec.py with new features whole the operations only work with port 135 (don't need smb connection) for AV evasion in Lateral Movement
        // Reference: https://github.com/XiaoliChan/wmiexec-Pro
        $string35 = /wmiexec\-Pro\.git/ nocase ascii wide
        // Description: The new generation of wmiexec.py with new features whole the operations only work with port 135 (don't need smb connection) for AV evasion in Lateral Movement
        // Reference: https://github.com/XiaoliChan/wmiexec-Pro
        $string36 = /wmiexec\-pro\.py/ nocase ascii wide
        // Description: The new generation of wmiexec.py with new features whole the operations only work with port 135 (don't need smb connection) for AV evasion in Lateral Movement
        // Reference: https://github.com/XiaoliChan/wmiexec-Pro
        $string37 = /wmiexec\-Pro\/tarball/ nocase ascii wide
        // Description: The new generation of wmiexec.py with new features whole the operations only work with port 135 (don't need smb connection) for AV evasion in Lateral Movement
        // Reference: https://github.com/XiaoliChan/wmiexec-Pro
        $string38 = /wmiexec\-Pro\/zipball/ nocase ascii wide
        // Description: The new generation of wmiexec.py with new features whole the operations only work with port 135 (don't need smb connection) for AV evasion in Lateral Movement
        // Reference: https://github.com/XiaoliChan/wmiexec-Pro
        $string39 = /wmipersist\.py/ nocase ascii wide
        // Description: The new generation of wmiexec.py with new features whole the operations only work with port 135 (don't need smb connection) for AV evasion in Lateral Movement
        // Reference: https://github.com/XiaoliChan/wmiexec-Pro
        $string40 = /XiaoliChan\/wmiexec\-Pro/ nocase ascii wide

    condition:
        any of them
}
