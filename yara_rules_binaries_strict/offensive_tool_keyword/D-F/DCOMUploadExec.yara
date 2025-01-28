rule DCOMUploadExec
{
    meta:
        description = "Detection patterns for the tool 'DCOMUploadExec' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DCOMUploadExec"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: DCOM Lateral movement POC abusing the IMsiServer interface - uploads and executes a payload remotely
        // Reference: https://github.com/deepinstinct/DCOMUploadExec
        $string1 = /\/DCOMUploadExec\.exe/ nocase ascii wide
        // Description: DCOM Lateral movement POC abusing the IMsiServer interface - uploads and executes a payload remotely
        // Reference: https://github.com/deepinstinct/DCOMUploadExec
        $string2 = /\/DCOMUploadExec\.git/ nocase ascii wide
        // Description: DCOM Lateral movement POC abusing the IMsiServer interface - uploads and executes a payload remotely
        // Reference: https://github.com/deepinstinct/DCOMUploadExec
        $string3 = /\[\+\]\sCreated\sa\sremote\sGAC\sfile\sstream/ nocase ascii wide
        // Description: DCOM Lateral movement POC abusing the IMsiServer interface - uploads and executes a payload remotely
        // Reference: https://github.com/deepinstinct/DCOMUploadExec
        $string4 = /\\DCOMUploadExec\.exe/ nocase ascii wide
        // Description: DCOM Lateral movement POC abusing the IMsiServer interface - uploads and executes a payload remotely
        // Reference: https://github.com/deepinstinct/DCOMUploadExec
        $string5 = /\\DCOMUploadExec\.sln/ nocase ascii wide
        // Description: DCOM Lateral movement POC abusing the IMsiServer interface - uploads and executes a payload remotely
        // Reference: https://github.com/deepinstinct/DCOMUploadExec
        $string6 = /\\DCOMUploadExec\-main/ nocase ascii wide
        // Description: DCOM Lateral movement POC abusing the IMsiServer interface - uploads and executes a payload remotely
        // Reference: https://github.com/deepinstinct/DCOMUploadExec
        $string7 = "57FD94EC-4361-43FD-AB9D-CDB254C0DE8F" nocase ascii wide
        // Description: DCOM Lateral movement POC abusing the IMsiServer interface - uploads and executes a payload remotely
        // Reference: https://github.com/deepinstinct/DCOMUploadExec
        $string8 = "781a54a1bb3fb0960ce374f79a50ba0870e824a5b2432ee8cb2de3b5b8883128" nocase ascii wide
        // Description: DCOM Lateral movement POC abusing the IMsiServer interface - uploads and executes a payload remotely
        // Reference: https://github.com/deepinstinct/DCOMUploadExec
        $string9 = "7bf6b6be-a29f-440a-9962-9fabc5d9665a" nocase ascii wide
        // Description: DCOM Lateral movement POC abusing the IMsiServer interface - uploads and executes a payload remotely
        // Reference: https://github.com/deepinstinct/DCOMUploadExec
        $string10 = /ASSEMBLY_PUBLIC_KEY.{0,100}136e5fbf23bb401e/ nocase ascii wide
        // Description: DCOM Lateral movement POC abusing the IMsiServer interface - uploads and executes a payload remotely
        // Reference: https://github.com/deepinstinct/DCOMUploadExec
        $string11 = "c4d95bff1eced83e423deb8555d636b02c290adba785a349bc776711bbc2841e" nocase ascii wide
        // Description: DCOM Lateral movement POC abusing the IMsiServer interface - uploads and executes a payload remotely
        // Reference: https://github.com/deepinstinct/DCOMUploadExec
        $string12 = /DCOMUploadExec\.exe\s/ nocase ascii wide
        // Description: DCOM Lateral movement POC abusing the IMsiServer interface - uploads and executes a payload remotely
        // Reference: https://github.com/deepinstinct/DCOMUploadExec
        $string13 = /DCOMUploadExec\-main\.zip/ nocase ascii wide
        // Description: DCOM Lateral movement POC abusing the IMsiServer interface - uploads and executes a payload remotely
        // Reference: https://github.com/deepinstinct/DCOMUploadExec
        $string14 = "deepinstinct/DCOMUploadExec" nocase ascii wide
        // Description: DCOM Lateral movement POC abusing the IMsiServer interface - uploads and executes a payload remotely
        // Reference: https://github.com/deepinstinct/DCOMUploadExec
        $string15 = "MSIEXEC - GAC backdoor installed" nocase ascii wide
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
        )) and any of ($string*)) or
        (filesize < 2MB and
        (
            any of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}
