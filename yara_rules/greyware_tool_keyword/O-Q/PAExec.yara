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
        $string2 = /\sPAExec\sservice/ nocase ascii wide
        // Description: PAExec is a freely-redistributable re-implementation of SysInternal/Microsoft's popular PsExec program
        // Reference: https://github.com/poweradminllc/PAExec
        $string3 = /\%SYSTEMROOT\%\\PAExec\-/ nocase ascii wide
        // Description: PAExec is a freely-redistributable re-implementation of SysInternal/Microsoft's popular PsExec program
        // Reference: https://github.com/poweradminllc/PAExec
        $string4 = /\/PAExec\.cpp/ nocase ascii wide
        // Description: PAExec is a freely-redistributable re-implementation of SysInternal/Microsoft's popular PsExec program
        // Reference: https://github.com/poweradminllc/PAExec
        $string5 = /\/paexec\.exe/ nocase ascii wide
        // Description: PAExec is a freely-redistributable re-implementation of SysInternal/Microsoft's popular PsExec program
        // Reference: https://github.com/poweradminllc/PAExec
        $string6 = /\/PAExec\.git/ nocase ascii wide
        // Description: PAExec is a freely-redistributable re-implementation of SysInternal/Microsoft's popular PsExec program
        // Reference: https://github.com/poweradminllc/PAExec
        $string7 = /\/paexec_eula\.txt/ nocase ascii wide
        // Description: PAExec is a freely-redistributable re-implementation of SysInternal/Microsoft's popular PsExec program
        // Reference: https://github.com/poweradminllc/PAExec
        $string8 = /\\PAExec\.cpp/ nocase ascii wide
        // Description: PAExec is a freely-redistributable re-implementation of SysInternal/Microsoft's popular PsExec program
        // Reference: https://github.com/poweradminllc/PAExec
        $string9 = /\\PAExec\.exe/ nocase ascii wide
        // Description: PAExec is a freely-redistributable re-implementation of SysInternal/Microsoft's popular PsExec program
        // Reference: https://github.com/poweradminllc/PAExec
        $string10 = /\\PAEXEC\.EXE\-.{0,1000}\.pf/ nocase ascii wide
        // Description: PAExec is a freely-redistributable re-implementation of SysInternal/Microsoft's popular PsExec program
        // Reference: https://github.com/poweradminllc/PAExec
        $string11 = /\\PAExec\.log/ nocase ascii wide
        // Description: PAExec is a freely-redistributable re-implementation of SysInternal/Microsoft's popular PsExec program
        // Reference: https://github.com/poweradminllc/PAExec
        $string12 = /\\paexec\.obj/ nocase ascii wide
        // Description: PAExec is a freely-redistributable re-implementation of SysInternal/Microsoft's popular PsExec program
        // Reference: https://github.com/poweradminllc/PAExec
        $string13 = /\\paexec\.pdb/ nocase ascii wide
        // Description: PAExec is a freely-redistributable re-implementation of SysInternal/Microsoft's popular PsExec program
        // Reference: https://github.com/poweradminllc/PAExec
        $string14 = /\\PAExec\.sln/ nocase ascii wide
        // Description: PAExec is a freely-redistributable re-implementation of SysInternal/Microsoft's popular PsExec program
        // Reference: https://github.com/poweradminllc/PAExec
        $string15 = /\\PAExec\\.{0,1000}\.exe/ nocase ascii wide
        // Description: PAExec is a freely-redistributable re-implementation of SysInternal/Microsoft's popular PsExec program
        // Reference: https://github.com/poweradminllc/PAExec
        $string16 = /\\paexec_eula\.txt/ nocase ascii wide
        // Description: PAExec is a freely-redistributable re-implementation of SysInternal/Microsoft's popular PsExec program
        // Reference: https://github.com/poweradminllc/PAExec
        $string17 = /\\PAExec_Move/ nocase ascii wide
        // Description: PAExec is a freely-redistributable re-implementation of SysInternal/Microsoft's popular PsExec program
        // Reference: https://github.com/poweradminllc/PAExec
        $string18 = /\\pipe\\PAExecErr/ nocase ascii wide
        // Description: PAExec is a freely-redistributable re-implementation of SysInternal/Microsoft's popular PsExec program
        // Reference: https://github.com/poweradminllc/PAExec
        $string19 = /\\pipe\\PAExecIn/ nocase ascii wide
        // Description: PAExec is a freely-redistributable re-implementation of SysInternal/Microsoft's popular PsExec program
        // Reference: https://github.com/poweradminllc/PAExec
        $string20 = /\\pipe\\PAExecOut/ nocase ascii wide
        // Description: PAExec is a freely-redistributable re-implementation of SysInternal/Microsoft's popular PsExec program
        // Reference: https://github.com/poweradminllc/PAExec
        $string21 = /2FEB96F5\-08E6\-48A3\-B306\-794277650A08/ nocase ascii wide
        // Description: PAExec is a freely-redistributable re-implementation of SysInternal/Microsoft's popular PsExec program
        // Reference: https://github.com/poweradminllc/PAExec
        $string22 = /2FEB96F5\-08E6\-48A3\-B306\-794277650A08/ nocase ascii wide
        // Description: PAExec is a freely-redistributable re-implementation of SysInternal/Microsoft's popular PsExec program
        // Reference: https://github.com/poweradminllc/PAExec
        $string23 = /Description\'\>PAExec\sApplication/ nocase ascii wide
        // Description: PAExec is a freely-redistributable re-implementation of SysInternal/Microsoft's popular PsExec program
        // Reference: https://github.com/poweradminllc/PAExec
        $string24 = /\'Details\'\>paexec\sapplication/ nocase ascii wide
        // Description: PAExec is a freely-redistributable re-implementation of SysInternal/Microsoft's popular PsExec program
        // Reference: https://github.com/poweradminllc/PAExec
        $string25 = /HINT\:\sPAExec\sprobably\sneeds\sto\sbe\s/ nocase ascii wide
        // Description: PAExec is a freely-redistributable re-implementation of SysInternal/Microsoft's popular PsExec program
        // Reference: https://github.com/poweradminllc/PAExec
        $string26 = /paexec\s\\\\/ nocase ascii wide
        // Description: PAExec is a freely-redistributable re-implementation of SysInternal/Microsoft's popular PsExec program
        // Reference: https://github.com/poweradminllc/PAExec
        $string27 = /PAExec\serror\swaiting\sfor\sapp\sto\sexit/ nocase ascii wide
        // Description: PAExec is a freely-redistributable re-implementation of SysInternal/Microsoft's popular PsExec program
        // Reference: https://github.com/poweradminllc/PAExec
        $string28 = /PAExec\sservice\s/ nocase ascii wide
        // Description: PAExec is a freely-redistributable re-implementation of SysInternal/Microsoft's popular PsExec program
        // Reference: https://github.com/poweradminllc/PAExec
        $string29 = /PAExec\sstarting\sprocess/ nocase ascii wide
        // Description: PAExec is a freely-redistributable re-implementation of SysInternal/Microsoft's popular PsExec program
        // Reference: https://github.com/poweradminllc/PAExec
        $string30 = /PAExec\stimed\sout\swaiting\sfor\sapp\sto\sexit/ nocase ascii wide
        // Description: PAExec is a freely-redistributable re-implementation of SysInternal/Microsoft's popular PsExec program
        // Reference: https://github.com/poweradminllc/PAExec
        $string31 = /paexec\.exe\s\\\\/ nocase ascii wide
        // Description: PAExec is a freely-redistributable re-implementation of SysInternal/Microsoft's popular PsExec program
        // Reference: https://github.com/poweradminllc/PAExec
        $string32 = /PAExec\.exe\s\-u\s/ nocase ascii wide
        // Description: PAExec is a freely-redistributable re-implementation of SysInternal/Microsoft's popular PsExec program
        // Reference: https://github.com/poweradminllc/PAExec
        $string33 = /PAExec\-master\.zip/ nocase ascii wide
        // Description: PAExec is a freely-redistributable re-implementation of SysInternal/Microsoft's popular PsExec program
        // Reference: https://github.com/poweradminllc/PAExec
        $string34 = /poweradmin\.com\/PAExec/ nocase ascii wide
        // Description: PAExec is a freely-redistributable re-implementation of SysInternal/Microsoft's popular PsExec program
        // Reference: https://github.com/poweradminllc/PAExec
        $string35 = /poweradminllc\/PAExec/ nocase ascii wide

    condition:
        any of them
}
