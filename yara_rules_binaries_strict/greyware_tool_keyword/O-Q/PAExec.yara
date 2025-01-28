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
        $string2 = " PAExec service" nocase ascii wide
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
        $string10 = /\\PAEXEC\.EXE\-.{0,100}\.pf/ nocase ascii wide
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
        $string15 = /\\PAExec\\.{0,100}\.exe/ nocase ascii wide
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
        $string21 = "2FEB96F5-08E6-48A3-B306-794277650A08" nocase ascii wide
        // Description: PAExec is a freely-redistributable re-implementation of SysInternal/Microsoft's popular PsExec program
        // Reference: https://github.com/poweradminllc/PAExec
        $string22 = "2FEB96F5-08E6-48A3-B306-794277650A08" nocase ascii wide
        // Description: PAExec is a freely-redistributable re-implementation of SysInternal/Microsoft's popular PsExec program
        // Reference: https://github.com/poweradminllc/PAExec
        $string23 = "Description'>PAExec Application" nocase ascii wide
        // Description: PAExec is a freely-redistributable re-implementation of SysInternal/Microsoft's popular PsExec program
        // Reference: https://github.com/poweradminllc/PAExec
        $string24 = "'Details'>paexec application" nocase ascii wide
        // Description: PAExec is a freely-redistributable re-implementation of SysInternal/Microsoft's popular PsExec program
        // Reference: https://github.com/poweradminllc/PAExec
        $string25 = "HINT: PAExec probably needs to be " nocase ascii wide
        // Description: PAExec is a freely-redistributable re-implementation of SysInternal/Microsoft's popular PsExec program
        // Reference: https://github.com/poweradminllc/PAExec
        $string26 = /paexec\s\\\\/ nocase ascii wide
        // Description: PAExec is a freely-redistributable re-implementation of SysInternal/Microsoft's popular PsExec program
        // Reference: https://github.com/poweradminllc/PAExec
        $string27 = "PAExec error waiting for app to exit" nocase ascii wide
        // Description: PAExec is a freely-redistributable re-implementation of SysInternal/Microsoft's popular PsExec program
        // Reference: https://github.com/poweradminllc/PAExec
        $string28 = "PAExec service " nocase ascii wide
        // Description: PAExec is a freely-redistributable re-implementation of SysInternal/Microsoft's popular PsExec program
        // Reference: https://github.com/poweradminllc/PAExec
        $string29 = "PAExec starting process" nocase ascii wide
        // Description: PAExec is a freely-redistributable re-implementation of SysInternal/Microsoft's popular PsExec program
        // Reference: https://github.com/poweradminllc/PAExec
        $string30 = "PAExec timed out waiting for app to exit" nocase ascii wide
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
        $string35 = "poweradminllc/PAExec" nocase ascii wide
        $metadata_regex_import = /\bimport\s+[a-zA-Z0-9_.]+\b/ nocase
        $metadata_regex_function = /function\s+[a-zA-Z_][a-zA-Z0-9_]*\(/ nocase ascii
        $metadata_regex_php = /<\?php/ nocase ascii
        $metadata_regex_createobject = /(CreateObject|WScript\.)/ nocase ascii
        $metadata_regex_script = /<script\b/ nocase ascii
        $metadata_regex_javascript = /(let\s|const\s|function\s|document\.|console\.)/ nocase ascii
        $metadata_regex_powershell = /(Write-Host|Get-[a-zA-Z]+|Invoke-|param\(|\.SYNOPSIS)/ nocase ascii
        $metadata_regex_batch = /@(echo\s|call\s|set\s|goto\s|if\s|for\s|rem\s)/ nocase ascii
        $metadata_regex_shebang = /^#!\// nocase ascii

    condition:
        ((filesize < 20MB and (
            uint16(0) == 0x5a4d or // Windows binary
            uint16(0) == 0x457f or // Linux ELF
            uint32be(0) == 0x7f454c46 or uint16(0) == 0xfeca or uint16(0) == 0xfacf or uint32(0) == 0xbebafeca or // macOS binary
            uint32(0) == 0x504B0304 or // Android APK, JAR
            uint32(0) == 0xCAFEBABE or // Java Class, Mach-O Universal Binary
            uint32(0) == 0x4D534346 or // Windows Cabinet File
            uint32(0) == 0xD0CF11E0 or // MSI Installer Package
            uint16(0) == 0x2321 or // Shebang (#!)
            uint16(0) == 0x3c3f // PHP and other script
        )) and 2 of ($string*)) or
        (filesize < 2MB and
        (
            2 of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}
