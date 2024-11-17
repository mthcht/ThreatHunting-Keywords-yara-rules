rule esxcli
{
    meta:
        description = "Detection patterns for the tool 'esxcli' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "esxcli"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: commands used by ransomware targeting ESXi hosts
        // Reference: https://medium.com/detect-fyi/detecting-and-responding-to-esxi-compromise-with-splunk-f33998ce7823
        $string1 = /esxcli\snetwork\sfirewall\sset\s\-enabled\sf/ nocase ascii wide
        // Description: commands used by ransomware targeting ESXi hosts
        // Reference: https://medium.com/detect-fyi/detecting-and-responding-to-esxi-compromise-with-splunk-f33998ce7823
        $string2 = /esxcli\ssystem\saccount\sadd/ nocase ascii wide
        // Description: commands used by ransomware targeting ESXi hosts
        // Reference: https://medium.com/detect-fyi/detecting-and-responding-to-esxi-compromise-with-splunk-f33998ce7823
        $string3 = /esxcli\ssystem\saccount\sremove/ nocase ascii wide
        // Description: commands used by ransomware targeting ESXi hosts
        // Reference: https://medium.com/detect-fyi/detecting-and-responding-to-esxi-compromise-with-splunk-f33998ce7823
        $string4 = /esxcli\ssystem\saccount\sset\s\-i\s.{0,100}\s\-s\st/ nocase ascii wide
        // Description: commands used by ransomware targeting ESXi hosts
        // Reference: https://medium.com/detect-fyi/detecting-and-responding-to-esxi-compromise-with-splunk-f33998ce7823
        $string5 = /esxcli\ssystem\sauditrecords\slocal\sdisable/ nocase ascii wide
        // Description: commands used by ransomware targeting ESXi hosts
        // Reference: https://medium.com/detect-fyi/detecting-and-responding-to-esxi-compromise-with-splunk-f33998ce7823
        $string6 = /esxcli\ssystem\spermission\slist/ nocase ascii wide
        // Description: commands used by ransomware targeting ESXi hosts
        // Reference: https://medium.com/detect-fyi/detecting-and-responding-to-esxi-compromise-with-splunk-f33998ce7823
        $string7 = /esxcli\ssystem\ssettings\sencryption\sset\s\-\srequire\-exec\-installed\-only\=F/ nocase ascii wide
        // Description: commands used by ransomware targeting ESXi hosts
        // Reference: https://medium.com/detect-fyi/detecting-and-responding-to-esxi-compromise-with-splunk-f33998ce7823
        $string8 = /esxcli\ssystem\ssettings\sencryption\sset\s\-\srequire\-secure\-boot\=F/ nocase ascii wide
        // Description: commands used by ransomware targeting ESXi hosts
        // Reference: https://medium.com/detect-fyi/detecting-and-responding-to-esxi-compromise-with-splunk-f33998ce7823
        $string9 = /esxcli\ssystem\ssettings\skernel\sset\s\-s\sexecInstalledOnly\s\-v\sF/ nocase ascii wide
        // Description: commands used by ransomware targeting ESXi hosts
        // Reference: https://medium.com/detect-fyi/detecting-and-responding-to-esxi-compromise-with-splunk-f33998ce7823
        $string10 = /esxcli\svm\sprocess\skill\s/ nocase ascii wide
        // Description: commands used by ransomware targeting ESXi hosts
        // Reference: https://medium.com/detect-fyi/detecting-and-responding-to-esxi-compromise-with-splunk-f33998ce7823
        $string11 = /esxcli\svm\sprocess\slist/ nocase ascii wide
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
