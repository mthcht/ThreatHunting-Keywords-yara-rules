rule Hak5_Rubber_Ducky
{
    meta:
        description = "Detection patterns for the tool 'Hak5 Rubber Ducky' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Hak5 Rubber Ducky"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: keystroke injection tool
        // Reference: https://github.com/mthcht/awesome-lists/blob/main/Lists/suspicious_usb_ids_list.csv
        $string1 = /HID\\VID_03EB\&PID_2401\&REV_0100/ nocase ascii wide
        // Description: keystroke injection tool
        // Reference: https://github.com/mthcht/awesome-lists/blob/main/Lists/suspicious_usb_ids_list.csv
        $string2 = /HID\\VID_03EB\&PID_2422\&REV_0100/ nocase ascii wide
        // Description: keystroke injection tool	
        // Reference: https://github.com/greghanley/ducky-decode-wiki/blob/master/Guide_Change_USB_VID_PID.wiki
        $string3 = /VID_03EB\&PID_2403/ nocase ascii wide
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
