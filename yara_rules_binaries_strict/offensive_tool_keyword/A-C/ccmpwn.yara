rule ccmpwn
{
    meta:
        description = "Detection patterns for the tool 'ccmpwn' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ccmpwn"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Lateral Movement script that leverages the CcmExec service to remotely hijack user sessions
        // Reference: https://github.com/mandiant/ccmpwn
        $string1 = /\sccmpwn\.py/ nocase ascii wide
        // Description: Lateral Movement script that leverages the CcmExec service to remotely hijack user sessions
        // Reference: https://github.com/mandiant/ccmpwn
        $string2 = /\sexec\s\-dll\s.{0,100}\.dll\s\-config\s.{0,100}\.config/ nocase ascii wide
        // Description: Lateral Movement script that leverages the CcmExec service to remotely hijack user sessions
        // Reference: https://github.com/mandiant/ccmpwn
        $string3 = /\.py\s.{0,100}\scoerce\s\-computer\s/ nocase ascii wide
        // Description: Lateral Movement script that leverages the CcmExec service to remotely hijack user sessions
        // Reference: https://github.com/mandiant/ccmpwn
        $string4 = /\/ccmpwn\.git/ nocase ascii wide
        // Description: Lateral Movement script that leverages the CcmExec service to remotely hijack user sessions
        // Reference: https://github.com/mandiant/ccmpwn
        $string5 = /\/ccmpwn\.py/ nocase ascii wide
        // Description: Lateral Movement script that leverages the CcmExec service to remotely hijack user sessions
        // Reference: https://github.com/mandiant/ccmpwn
        $string6 = /\\ccmpwn\.py/ nocase ascii wide
        // Description: Lateral Movement script that leverages the CcmExec service to remotely hijack user sessions
        // Reference: https://github.com/mandiant/ccmpwn
        $string7 = /\\ccmpwn\\/ nocase ascii wide
        // Description: Lateral Movement script that leverages the CcmExec service to remotely hijack user sessions
        // Reference: https://github.com/mandiant/ccmpwn
        $string8 = /\\http_SCNotification\.exe/ nocase ascii wide
        // Description: Lateral Movement script that leverages the CcmExec service to remotely hijack user sessions
        // Reference: https://github.com/mandiant/ccmpwn
        $string9 = /\\smb_SCNotification\.exe/ nocase ascii wide
        // Description: Lateral Movement script that leverages the CcmExec service to remotely hijack user sessions
        // Reference: https://github.com/mandiant/ccmpwn
        $string10 = /5c611fb030683dba08662997836b3b308c0278130bf2eee6ac6af6a4332285fe/ nocase ascii wide
        // Description: Lateral Movement script that leverages the CcmExec service to remotely hijack user sessions
        // Reference: https://github.com/mandiant/ccmpwn
        $string11 = /CcmExec\smight\snot\sbe\sinstalled\son\starget/ nocase ascii wide
        // Description: Lateral Movement script that leverages the CcmExec service to remotely hijack user sessions
        // Reference: https://github.com/mandiant/ccmpwn
        $string12 = /CcmExec\sservice\snot\saccessible\son\sremote\ssystem\!\s\:\(/ nocase ascii wide
        // Description: Lateral Movement script that leverages the CcmExec service to remotely hijack user sessions
        // Reference: https://github.com/mandiant/ccmpwn
        $string13 = /Downloading\soriginal\sSCNotification\.exe\.config\svia\sSMB/ nocase ascii wide
        // Description: Lateral Movement script that leverages the CcmExec service to remotely hijack user sessions
        // Reference: https://github.com/mandiant/ccmpwn
        $string14 = /impacket\.dcerpc/ nocase ascii wide
        // Description: Lateral Movement script that leverages the CcmExec service to remotely hijack user sessions
        // Reference: https://github.com/mandiant/ccmpwn
        $string15 = /mandiant\/ccmpwn/ nocase ascii wide
        // Description: Lateral Movement script that leverages the CcmExec service to remotely hijack user sessions
        // Reference: https://github.com/mandiant/ccmpwn
        $string16 = /SCNotification\.exe\.config\.malicious/ nocase ascii wide
        // Description: Lateral Movement script that leverages the CcmExec service to remotely hijack user sessions
        // Reference: https://github.com/mandiant/ccmpwn
        $string17 = /smbclient\.getFile\(\'C\$\'\,\s\'Windows\/CCM\/SCNotification\.exe\.config/ nocase ascii wide
        // Description: Lateral Movement script that leverages the CcmExec service to remotely hijack user sessions
        // Reference: https://github.com/mandiant/ccmpwn
        $string18 = /Starting\sCcmExec\sservice\.\sWait\saround\s30\sseconds\sfor\sSCNotification\.exe\sto\srun\sconfig\sfile/ nocase ascii wide
        // Description: Lateral Movement script that leverages the CcmExec service to remotely hijack user sessions
        // Reference: https://github.com/mandiant/ccmpwn
        $string19 = /templates\/http_SCNotification\.exe/ nocase ascii wide
        // Description: Lateral Movement script that leverages the CcmExec service to remotely hijack user sessions
        // Reference: https://github.com/mandiant/ccmpwn
        $string20 = /templates\/smb_SCNotification\.exe/ nocase ascii wide
        // Description: Lateral Movement script that leverages the CcmExec service to remotely hijack user sessions
        // Reference: https://github.com/mandiant/ccmpwn
        $string21 = /Uploading\smalicious\sDLL\svia\sSMB/ nocase ascii wide
        // Description: Lateral Movement script that leverages the CcmExec service to remotely hijack user sessions
        // Reference: https://github.com/mandiant/ccmpwn
        $string22 = /Uploading\smalicious\sSCNotification\.exe\.config\svia\sSMB/ nocase ascii wide
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
