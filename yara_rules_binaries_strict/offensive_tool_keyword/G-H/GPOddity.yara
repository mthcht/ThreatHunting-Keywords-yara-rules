rule GPOddity
{
    meta:
        description = "Detection patterns for the tool 'GPOddity' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "GPOddity"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: GPO attack vectors through NTLM relaying
        // Reference: https://github.com/synacktiv/GPOddity
        $string1 = /\s\'GPODDITY\$\'\s/ nocase ascii wide
        // Description: GPO attack vectors through NTLM relaying
        // Reference: https://github.com/synacktiv/GPOddity
        $string2 = /\s\-\-gpo\-id\s.{0,100}\s\-\-domain\s.{0,100}\s\-\-command\s/ nocase ascii wide
        // Description: GPO attack vectors through NTLM relaying
        // Reference: https://github.com/synacktiv/GPOddity
        $string3 = /\s\-\-gpo\-id\s.{0,100}\s\-\-gpo\-type\s.{0,100}\s\-\-no\-smb\-server\s/ nocase ascii wide
        // Description: GPO attack vectors through NTLM relaying
        // Reference: https://github.com/synacktiv/GPOddity
        $string4 = " --rogue-smbserver-ip " nocase ascii wide
        // Description: GPO attack vectors through NTLM relaying
        // Reference: https://github.com/synacktiv/GPOddity
        $string5 = " --rogue-smbserver-share " nocase ascii wide
        // Description: GPO attack vectors through NTLM relaying
        // Reference: https://github.com/synacktiv/GPOddity
        $string6 = /\(not\slaunching\sGPOddity\sSMB\sserver\)/ nocase ascii wide
        // Description: GPO attack vectors through NTLM relaying
        // Reference: https://github.com/synacktiv/GPOddity
        $string7 = /\/GPOddity\.git/ nocase ascii wide
        // Description: GPO attack vectors through NTLM relaying
        // Reference: https://github.com/synacktiv/GPOddity
        $string8 = "/GPOddity/" nocase ascii wide
        // Description: GPO attack vectors through NTLM relaying
        // Reference: https://github.com/synacktiv/GPOddity
        $string9 = /\[\!\]\sFailed\sto\sdownload\slegitimate\sGPO\sfrom\sSYSVOL\s\(dc_ip\:/ nocase ascii wide
        // Description: GPO attack vectors through NTLM relaying
        // Reference: https://github.com/synacktiv/GPOddity
        $string10 = /\[\!\]\sFailed\sto\swrite\smalicious\sscheduled\stask\sto\sdownloaded\sGPO\.\sExiting/ nocase ascii wide
        // Description: GPO attack vectors through NTLM relaying
        // Reference: https://github.com/synacktiv/GPOddity
        $string11 = /\[.{0,100}\]\sDownloading\sthe\slegitimate\sGPO\sfrom\sSYSVOL/ nocase ascii wide
        // Description: GPO attack vectors through NTLM relaying
        // Reference: https://github.com/synacktiv/GPOddity
        $string12 = /\[.{0,100}\]\sInjecting\smalicious\sscheduled\stask\sinto\sdownloaded\sGPO/ nocase ascii wide
        // Description: GPO attack vectors through NTLM relaying
        // Reference: https://github.com/synacktiv/GPOddity
        $string13 = /\[.{0,100}\]\sUpdating\sdownloaded\sGPO\sversion\snumber\sto\sensure\sautomatic\sGPO\sapplication/ nocase ascii wide
        // Description: GPO attack vectors through NTLM relaying
        // Reference: https://github.com/synacktiv/GPOddity
        $string14 = /\[\+\]\sSuccessfully\sdownloaded\slegitimate\sGPO\sfrom\sSYSVOL\sto\s/ nocase ascii wide
        // Description: GPO attack vectors through NTLM relaying
        // Reference: https://github.com/synacktiv/GPOddity
        $string15 = /\[\+\]\sSuccessfully\sinjected\smalicious\sscheduled\stask/ nocase ascii wide
        // Description: GPO attack vectors through NTLM relaying
        // Reference: https://github.com/synacktiv/GPOddity
        $string16 = /\[\+\]\sSuccessfully\sspoofed\sGPC\sgPCFileSysPath\sattribute/ nocase ascii wide
        // Description: GPO attack vectors through NTLM relaying
        // Reference: https://github.com/synacktiv/GPOddity
        $string17 = /\\GPOddity\\/ nocase ascii wide
        // Description: GPO attack vectors through NTLM relaying
        // Reference: https://github.com/synacktiv/GPOddity
        $string18 = "=== GENERATING MALICIOUS GROUP POLICY TEMPLATE ===" nocase ascii wide
        // Description: GPO attack vectors through NTLM relaying
        // Reference: https://github.com/synacktiv/GPOddity
        $string19 = "46993522-7D77-4B59-9B77-F82082DE9D81" nocase ascii wide
        // Description: GPO attack vectors through NTLM relaying
        // Reference: https://github.com/synacktiv/GPOddity
        $string20 = "Could not write NTLM Hashes to the specified JTR_Dump_Path " nocase ascii wide
        // Description: GPO attack vectors through NTLM relaying
        // Reference: https://github.com/synacktiv/GPOddity
        $string21 = /Couldn\'t\sclone\sGPO\s\{\}\s\(maybe\sit\sdoes\snot\sexist\?/ nocase ascii wide
        // Description: GPO attack vectors through NTLM relaying
        // Reference: https://github.com/synacktiv/GPOddity
        $string22 = /from\shelpers\..{0,100}_smbserver\s.{0,100}\simport\sSimpleSMBServer/ nocase ascii wide
        // Description: GPO attack vectors through NTLM relaying
        // Reference: https://github.com/synacktiv/GPOddity
        $string23 = /gpoddity\.py/ nocase ascii wide
        // Description: GPO attack vectors through NTLM relaying
        // Reference: https://github.com/synacktiv/GPOddity
        $string24 = /gpoddity_smbserver\.py/ nocase ascii wide
        // Description: GPO attack vectors through NTLM relaying
        // Reference: https://github.com/synacktiv/GPOddity
        $string25 = "GPOddity-master" nocase ascii wide
        // Description: GPO attack vectors through NTLM relaying
        // Reference: https://github.com/synacktiv/GPOddity
        $string26 = /helpers\.gpoddity_smbserver/ nocase ascii wide
        // Description: GPO attack vectors through NTLM relaying
        // Reference: https://github.com/synacktiv/GPOddity
        $string27 = /If\sthe\sattack\sis\ssuccessful.{0,100}\syou\swill\ssee\sauthentication\slogs\sof\smachines\sretrieving\sand\sexecuting\sthe\smalicious\sGPO/ nocase ascii wide
        // Description: GPO attack vectors through NTLM relaying
        // Reference: https://github.com/synacktiv/GPOddity
        $string28 = /\-\-just\-clean.{0,100}cleaning\/to_clean\.txt/ nocase ascii wide
        // Description: GPO attack vectors through NTLM relaying
        // Reference: https://github.com/synacktiv/GPOddity
        $string29 = "LAUNCHING GPODDITY SMB SERVER AND WAITING FOR GPO REQUESTS" nocase ascii wide
        // Description: GPO attack vectors through NTLM relaying
        // Reference: https://github.com/synacktiv/GPOddity
        $string30 = "net user john H4x00r123" nocase ascii wide
        // Description: GPO attack vectors through NTLM relaying
        // Reference: https://github.com/synacktiv/GPOddity
        $string31 = /scheduledtask_utils\.py\s/ nocase ascii wide
        // Description: GPO attack vectors through NTLM relaying
        // Reference: https://github.com/synacktiv/GPOddity
        $string32 = "SPOOFING GROUP POLICY TEMPLATE LOCATION THROUGH gPCFileSysPath" nocase ascii wide
        // Description: GPO attack vectors through NTLM relaying
        // Reference: https://github.com/synacktiv/GPOddity
        $string33 = "synacktiv/GPOddity" nocase ascii wide
        // Description: GPO attack vectors through NTLM relaying
        // Reference: https://github.com/synacktiv/GPOddity
        $string34 = "synacktiv_gpoddity" nocase ascii wide
        // Description: GPO attack vectors through NTLM relaying
        // Reference: https://github.com/synacktiv/GPOddity
        $string35 = "You are trying to target a User Group Policy Object while running the embedded SMB server" nocase ascii wide
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
