rule wmiexec_pro
{
    meta:
        description = "Detection patterns for the tool 'wmiexec-pro' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "wmiexec-pro"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: The new generation of wmiexec.py with new features whole the operations only work with port 135 (don't need smb connection) for AV evasion in lateral movement
        // Reference: https://github.com/XiaoliChan/wmiexec-Pro
        $string1 = /.{0,1000}\sexec\-command\s\-clear.{0,1000}/ nocase ascii wide
        // Description: The new generation of wmiexec.py with new features whole the operations only work with port 135 (don't need smb connection) for AV evasion in lateral movement
        // Reference: https://github.com/XiaoliChan/wmiexec-Pro
        $string2 = /.{0,1000}\sexec\-command\s\-command\s.{0,1000}/ nocase ascii wide
        // Description: The new generation of wmiexec.py with new features whole the operations only work with port 135 (don't need smb connection) for AV evasion in lateral movement
        // Reference: https://github.com/XiaoliChan/wmiexec-Pro
        $string3 = /.{0,1000}\sexec\-command\s\-shell.{0,1000}/ nocase ascii wide
        // Description: The new generation of wmiexec.py with new features whole the operations only work with port 135 (don't need smb connection) for AV evasion in lateral movement
        // Reference: https://github.com/XiaoliChan/wmiexec-Pro
        $string4 = /.{0,1000}\sfiletransfer\s\-download\s\-src\-file\s.{0,1000}\.exe.{0,1000}\/tmp.{0,1000}/ nocase ascii wide
        // Description: The new generation of wmiexec.py with new features whole the operations only work with port 135 (don't need smb connection) for AV evasion in lateral movement
        // Reference: https://github.com/XiaoliChan/wmiexec-Pro
        $string5 = /.{0,1000}\sfiletransfer\s\-upload\s\-src\-file\s.{0,1000}\.exe.{0,1000}\\temp.{0,1000}/ nocase ascii wide
        // Description: The new generation of wmiexec.py with new features whole the operations only work with port 135 (don't need smb connection) for AV evasion in lateral movement
        // Reference: https://github.com/XiaoliChan/wmiexec-Pro
        $string6 = /.{0,1000}\s\-no\-pass\srid\-hijack.{0,1000}/ nocase ascii wide
        // Description: The new generation of wmiexec.py with new features whole the operations only work with port 135 (don't need smb connection) for AV evasion in lateral movement
        // Reference: https://github.com/XiaoliChan/wmiexec-Pro
        $string7 = /.{0,1000}\srid\-hijack\s\-.{0,1000}/ nocase ascii wide
        // Description: The new generation of wmiexec.py with new features whole the operations only work with port 135 (don't need smb connection) for AV evasion in lateral movement
        // Reference: https://github.com/XiaoliChan/wmiexec-Pro
        $string8 = /.{0,1000}\sservice\s\-dump\sall\-services\.json.{0,1000}/ nocase ascii wide
        // Description: The new generation of wmiexec.py with new features whole the operations only work with port 135 (don't need smb connection) for AV evasion in lateral movement
        // Reference: https://github.com/XiaoliChan/wmiexec-Pro
        $string9 = /.{0,1000}\.py\s.{0,1000}\samsi\s\-disable.{0,1000}/ nocase ascii wide
        // Description: The new generation of wmiexec.py with new features whole the operations only work with port 135 (don't need smb connection) for AV evasion in lateral movement
        // Reference: https://github.com/XiaoliChan/wmiexec-Pro
        $string10 = /.{0,1000}\.py\s.{0,1000}\samsi\s\-enable.{0,1000}/ nocase ascii wide
        // Description: The new generation of wmiexec.py with new features whole the operations only work with port 135 (don't need smb connection) for AV evasion in lateral movement
        // Reference: https://github.com/XiaoliChan/wmiexec-Pro
        $string11 = /.{0,1000}\.py.{0,1000}\sservice\s\-action\screate\s\-service\-name\s.{0,1000}/ nocase ascii wide
        // Description: The new generation of wmiexec.py with new features whole the operations only work with port 135 (don't need smb connection) for AV evasion in lateral movement
        // Reference: https://github.com/XiaoliChan/wmiexec-Pro
        $string12 = /.{0,1000}\/wmiexec\-Pro.{0,1000}/ nocase ascii wide
        // Description: The new generation of wmiexec.py with new features whole the operations only work with port 135 (don't need smb connection) for AV evasion in lateral movement
        // Reference: https://github.com/XiaoliChan/wmiexec-Pro
        $string13 = /.{0,1000}C:\\aab\.txt.{0,1000}/ nocase ascii wide
        // Description: The new generation of wmiexec.py with new features whole the operations only work with port 135 (don't need smb connection) for AV evasion in lateral movement
        // Reference: https://github.com/XiaoliChan/wmiexec-Pro
        $string14 = /.{0,1000}ClearEventlog\.vbs.{0,1000}/ nocase ascii wide
        // Description: The new generation of wmiexec.py with new features whole the operations only work with port 135 (don't need smb connection) for AV evasion in lateral movement
        // Reference: https://github.com/XiaoliChan/wmiexec-Pro
        $string15 = /.{0,1000}eventlog\s\-risk\-i\-know.{0,1000}/ nocase ascii wide
        // Description: The new generation of wmiexec.py with new features whole the operations only work with port 135 (don't need smb connection) for AV evasion in lateral movement
        // Reference: https://github.com/XiaoliChan/wmiexec-Pro
        $string16 = /.{0,1000}eventlog_fucker\.py.{0,1000}/ nocase ascii wide
        // Description: The new generation of wmiexec.py with new features whole the operations only work with port 135 (don't need smb connection) for AV evasion in lateral movement
        // Reference: https://github.com/XiaoliChan/wmiexec-Pro
        $string17 = /.{0,1000}Exec\-Command\-Silent\.vbs.{0,1000}/ nocase ascii wide
        // Description: The new generation of wmiexec.py with new features whole the operations only work with port 135 (don't need smb connection) for AV evasion in lateral movement
        // Reference: https://github.com/XiaoliChan/wmiexec-Pro
        $string18 = /.{0,1000}GrantSamAccessPermission\.vbs.{0,1000}/ nocase ascii wide
        // Description: The new generation of wmiexec.py with new features whole the operations only work with port 135 (don't need smb connection) for AV evasion in lateral movement
        // Reference: https://github.com/XiaoliChan/wmiexec-Pro
        $string19 = /.{0,1000}modules\/enumrate\.py.{0,1000}/ nocase ascii wide
        // Description: The new generation of wmiexec.py with new features whole the operations only work with port 135 (don't need smb connection) for AV evasion in lateral movement
        // Reference: https://github.com/XiaoliChan/wmiexec-Pro
        $string20 = /.{0,1000}rid_hijack\.py.{0,1000}/ nocase ascii wide
        // Description: The new generation of wmiexec.py with new features whole the operations only work with port 135 (don't need smb connection) for AV evasion in lateral movement
        // Reference: https://github.com/XiaoliChan/wmiexec-Pro
        $string21 = /.{0,1000}wmiexec\-Pro\.git.{0,1000}/ nocase ascii wide
        // Description: The new generation of wmiexec.py with new features whole the operations only work with port 135 (don't need smb connection) for AV evasion in lateral movement
        // Reference: https://github.com/XiaoliChan/wmiexec-Pro
        $string22 = /.{0,1000}wmiexec\-pro\.py.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
