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
        $string13 = /C\:\\aab\.txt/ nocase ascii wide
        // Description: The new generation of wmiexec.py with new features whole the operations only work with port 135 (don't need smb connection) for AV evasion in Lateral Movement
        // Reference: https://github.com/XiaoliChan/wmiexec-Pro
        $string14 = /ClearEventlog\.vbs/ nocase ascii wide
        // Description: The new generation of wmiexec.py with new features whole the operations only work with port 135 (don't need smb connection) for AV evasion in Lateral Movement
        // Reference: https://github.com/XiaoliChan/wmiexec-Pro
        $string15 = /eventlog\s\-risk\-i\-know/ nocase ascii wide
        // Description: The new generation of wmiexec.py with new features whole the operations only work with port 135 (don't need smb connection) for AV evasion in Lateral Movement
        // Reference: https://github.com/XiaoliChan/wmiexec-Pro
        $string16 = /eventlog_fucker\.py/ nocase ascii wide
        // Description: The new generation of wmiexec.py with new features whole the operations only work with port 135 (don't need smb connection) for AV evasion in Lateral Movement
        // Reference: https://github.com/XiaoliChan/wmiexec-Pro
        $string17 = /Exec\-Command\-Silent\.vbs/ nocase ascii wide
        // Description: The new generation of wmiexec.py with new features whole the operations only work with port 135 (don't need smb connection) for AV evasion in Lateral Movement
        // Reference: https://github.com/XiaoliChan/wmiexec-Pro
        $string18 = /GrantSamAccessPermission\.vbs/ nocase ascii wide
        // Description: The new generation of wmiexec.py with new features whole the operations only work with port 135 (don't need smb connection) for AV evasion in Lateral Movement
        // Reference: https://github.com/XiaoliChan/wmiexec-Pro
        $string19 = /modules\/enumrate\.py/ nocase ascii wide
        // Description: The new generation of wmiexec.py with new features whole the operations only work with port 135 (don't need smb connection) for AV evasion in Lateral Movement
        // Reference: https://github.com/XiaoliChan/wmiexec-Pro
        $string20 = /rid_hijack\.py/ nocase ascii wide
        // Description: The new generation of wmiexec.py with new features whole the operations only work with port 135 (don't need smb connection) for AV evasion in Lateral Movement
        // Reference: https://github.com/XiaoliChan/wmiexec-Pro
        $string21 = /wmiexec\-Pro\.git/ nocase ascii wide
        // Description: The new generation of wmiexec.py with new features whole the operations only work with port 135 (don't need smb connection) for AV evasion in Lateral Movement
        // Reference: https://github.com/XiaoliChan/wmiexec-Pro
        $string22 = /wmiexec\-pro\.py/ nocase ascii wide

    condition:
        any of them
}
