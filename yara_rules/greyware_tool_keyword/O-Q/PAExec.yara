rule PAExec
{
    meta:
        description = "Detection patterns for the tool 'PAExec' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PAExec"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: PAExec is a freely-redistributable re-implementation of SysInternal/Microsoft's popular PsExec program
        // Reference: https://github.com/poweradminllc/PAExec
        $string1 = /\s\-csrc\sC\:\\\\Windows\\\\notepad\.exe\s\-c\scmd\.exe/ nocase ascii wide
        // Description: PAExec is a freely-redistributable re-implementation of SysInternal/Microsoft's popular PsExec program
        // Reference: https://github.com/poweradminllc/PAExec
        $string2 = /\%SYSTEMROOT\%\\PAExec\-/ nocase ascii wide
        // Description: PAExec is a freely-redistributable re-implementation of SysInternal/Microsoft's popular PsExec program
        // Reference: https://github.com/poweradminllc/PAExec
        $string3 = /\/PAExec\.cpp/ nocase ascii wide
        // Description: PAExec is a freely-redistributable re-implementation of SysInternal/Microsoft's popular PsExec program
        // Reference: https://github.com/poweradminllc/PAExec
        $string4 = /\/paexec\.exe/ nocase ascii wide
        // Description: PAExec is a freely-redistributable re-implementation of SysInternal/Microsoft's popular PsExec program
        // Reference: https://github.com/poweradminllc/PAExec
        $string5 = /\/PAExec\.git/ nocase ascii wide
        // Description: PAExec is a freely-redistributable re-implementation of SysInternal/Microsoft's popular PsExec program
        // Reference: https://github.com/poweradminllc/PAExec
        $string6 = /\\PAExec\.cpp/ nocase ascii wide
        // Description: PAExec is a freely-redistributable re-implementation of SysInternal/Microsoft's popular PsExec program
        // Reference: https://github.com/poweradminllc/PAExec
        $string7 = /\\PAEXEC\.EXE\-.{0,1000}\.pf/ nocase ascii wide
        // Description: PAExec is a freely-redistributable re-implementation of SysInternal/Microsoft's popular PsExec program
        // Reference: https://github.com/poweradminllc/PAExec
        $string8 = /\\PAExecErr/ nocase ascii wide
        // Description: PAExec is a freely-redistributable re-implementation of SysInternal/Microsoft's popular PsExec program
        // Reference: https://github.com/poweradminllc/PAExec
        $string9 = /\\PAExecIn/ nocase ascii wide
        // Description: PAExec is a freely-redistributable re-implementation of SysInternal/Microsoft's popular PsExec program
        // Reference: https://github.com/poweradminllc/PAExec
        $string10 = /\\PAExecOut/ nocase ascii wide
        // Description: PAExec is a freely-redistributable re-implementation of SysInternal/Microsoft's popular PsExec program
        // Reference: https://github.com/poweradminllc/PAExec
        $string11 = /2FEB96F5\-08E6\-48A3\-B306\-794277650A08/ nocase ascii wide
        // Description: PAExec is a freely-redistributable re-implementation of SysInternal/Microsoft's popular PsExec program
        // Reference: https://github.com/poweradminllc/PAExec
        $string12 = /Description\'\>PAExec\sApplication/ nocase ascii wide
        // Description: PAExec is a freely-redistributable re-implementation of SysInternal/Microsoft's popular PsExec program
        // Reference: https://github.com/poweradminllc/PAExec
        $string13 = /\'Details\'\>paexec\sapplication/ nocase ascii wide
        // Description: PAExec is a freely-redistributable re-implementation of SysInternal/Microsoft's popular PsExec program
        // Reference: https://github.com/poweradminllc/PAExec
        $string14 = /paexec\s\\\\/ nocase ascii wide
        // Description: PAExec is a freely-redistributable re-implementation of SysInternal/Microsoft's popular PsExec program
        // Reference: https://github.com/poweradminllc/PAExec
        $string15 = /paexec\.exe\s\\\\/ nocase ascii wide
        // Description: PAExec is a freely-redistributable re-implementation of SysInternal/Microsoft's popular PsExec program
        // Reference: https://github.com/poweradminllc/PAExec
        $string16 = /PAExec\.exe\s\-u\s/ nocase ascii wide
        // Description: PAExec is a freely-redistributable re-implementation of SysInternal/Microsoft's popular PsExec program
        // Reference: https://github.com/poweradminllc/PAExec
        $string17 = /PAExec\-master\.zip/ nocase ascii wide
        // Description: PAExec is a freely-redistributable re-implementation of SysInternal/Microsoft's popular PsExec program
        // Reference: https://github.com/poweradminllc/PAExec
        $string18 = /poweradminllc\/PAExec/ nocase ascii wide

    condition:
        any of them
}
