rule Eventlogedit_evt__General
{
    meta:
        description = "Detection patterns for the tool 'Eventlogedit-evt--General' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Eventlogedit-evt--General"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Remove individual lines from Windows Event Viewer Log (EVT) files
        // Reference: https://github.com/3gstudent/Eventlogedit-evt--General
        $string1 = /\/Eventlogedit\-evt\-\-General\.git/ nocase ascii wide
        // Description: Remove individual lines from Windows Event Viewer Log (EVT) files
        // Reference: https://github.com/3gstudent/Eventlogedit-evt--General
        $string2 = /\\evtDeleteRecordbyGetHandle\.cpp/ nocase ascii wide
        // Description: Remove individual lines from Windows Event Viewer Log (EVT) files
        // Reference: https://github.com/3gstudent/Eventlogedit-evt--General
        $string3 = /\\evtDeleteRecordbyGetHandle\.exe/ nocase ascii wide
        // Description: Remove individual lines from Windows Event Viewer Log (EVT) files
        // Reference: https://github.com/3gstudent/Eventlogedit-evt--General
        $string4 = /\\evtDeleteRecordofFile\.cpp/ nocase ascii wide
        // Description: Remove individual lines from Windows Event Viewer Log (EVT) files
        // Reference: https://github.com/3gstudent/Eventlogedit-evt--General
        $string5 = /\\evtDeleteRecordofFile\.exe/ nocase ascii wide
        // Description: Remove individual lines from Windows Event Viewer Log (EVT) files
        // Reference: https://github.com/3gstudent/Eventlogedit-evt--General
        $string6 = /\\evtModifyRecordbyGetHandle\.cpp/ nocase ascii wide
        // Description: Remove individual lines from Windows Event Viewer Log (EVT) files
        // Reference: https://github.com/3gstudent/Eventlogedit-evt--General
        $string7 = /\\evtModifyRecordbyGetHandle\.exe/ nocase ascii wide
        // Description: Remove individual lines from Windows Event Viewer Log (EVT) files
        // Reference: https://github.com/3gstudent/Eventlogedit-evt--General
        $string8 = /\\evtQueryRecordbyGetHandle\.cpp/ nocase ascii wide
        // Description: Remove individual lines from Windows Event Viewer Log (EVT) files
        // Reference: https://github.com/3gstudent/Eventlogedit-evt--General
        $string9 = /\\evtQueryRecordbyGetHandle\.exe/ nocase ascii wide
        // Description: Remove individual lines from Windows Event Viewer Log (EVT) files
        // Reference: https://github.com/3gstudent/Eventlogedit-evt--General
        $string10 = /3gstudent\.github\.io\/Windows\-Event\-Viewer\-Log\-/ nocase ascii wide
        // Description: Remove individual lines from Windows Event Viewer Log (EVT) files
        // Reference: https://github.com/3gstudent/Eventlogedit-evt--General
        $string11 = "3gstudent/Eventlogedit-evt--General" nocase ascii wide
        // Description: Remove individual lines from Windows Event Viewer Log (EVT) files
        // Reference: https://github.com/3gstudent/Eventlogedit-evt--General
        $string12 = "75ae186f6b5f926d7d538642d1258d028eaf404859813c5a0ce53df00115d7ee" nocase ascii wide
        // Description: Remove individual lines from Windows Event Viewer Log (EVT) files
        // Reference: https://github.com/3gstudent/Eventlogedit-evt--General
        $string13 = "7c43dca2c565e2c362c1085358213802a55f05d911560b689bbd138225e8d6d7" nocase ascii wide
        // Description: Remove individual lines from Windows Event Viewer Log (EVT) files
        // Reference: https://github.com/3gstudent/Eventlogedit-evt--General
        $string14 = "8613f6bd93b3ef201a4ef71a88d67c78cbbe693f71729eecf58d3ef06306610f" nocase ascii wide
        // Description: Remove individual lines from Windows Event Viewer Log (EVT) files
        // Reference: https://github.com/3gstudent/Eventlogedit-evt--General
        $string15 = /Delete\sspecified\sevt\sfile\'s\seventlog\srecord\.You\sneed\sto\sset\sStartTime\sand\sEndTime/ nocase ascii wide
        // Description: Remove individual lines from Windows Event Viewer Log (EVT) files
        // Reference: https://github.com/3gstudent/Eventlogedit-evt--General
        $string16 = /Delete\sspecified\sevt\sfile\'s\seventlog\srecord\.You\sneed\sto\sset\sStartTime\sand\sEndTime/ nocase ascii wide
        // Description: Remove individual lines from Windows Event Viewer Log (EVT) files
        // Reference: https://github.com/3gstudent/Eventlogedit-evt--General
        $string17 = "eb66eddca2e0c2a6b40ab6be4a159be5c81ee9f1dd3b7cc42df7c017ae06ee45" nocase ascii wide
        // Description: Remove individual lines from Windows Event Viewer Log (EVT) files
        // Reference: https://github.com/3gstudent/Eventlogedit-evt--General
        $string18 = /Modify\sthe\sselected\srecords\sof\sthe\sWindows\sEvent\sViewer\sLog\s\(EVT/ nocase ascii wide
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
