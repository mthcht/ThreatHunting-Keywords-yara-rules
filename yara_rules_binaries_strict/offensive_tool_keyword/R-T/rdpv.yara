rule rdpv
{
    meta:
        description = "Detection patterns for the tool 'rdpv' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "rdpv"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: RemoteDesktopPassView is a small utility that reveals the password stored by Microsoft Remote Desktop Connection utility inside the .rdp files.
        // Reference: https://www.nirsoft.net/utils/remote_desktop_password.html
        $string1 = /\srdpv\.exe/ nocase ascii wide
        // Description: RemoteDesktopPassView is a small utility that reveals the password stored by Microsoft Remote Desktop Connection utility inside the .rdp files.
        // Reference: https://www.nirsoft.net/utils/remote_desktop_password.html
        $string2 = /\/rdpv\.exe/ nocase ascii wide
        // Description: RemoteDesktopPassView is a small utility that reveals the password stored by Microsoft Remote Desktop Connection utility inside the .rdp files.
        // Reference: https://www.nirsoft.net/utils/remote_desktop_password.html
        $string3 = /\/toolsdownload\/rdpv\.zip/ nocase ascii wide
        // Description: RemoteDesktopPassView is a small utility that reveals the password stored by Microsoft Remote Desktop Connection utility inside the .rdp files.
        // Reference: https://www.nirsoft.net/utils/remote_desktop_password.html
        $string4 = /\\rdpv\.exe/ nocase ascii wide
        // Description: RemoteDesktopPassView is a small utility that reveals the password stored by Microsoft Remote Desktop Connection utility inside the .rdp files.
        // Reference: https://www.nirsoft.net/utils/remote_desktop_password.html
        $string5 = ">Password Recovery for Remote Desktop<" nocase ascii wide
        // Description: RemoteDesktopPassView is a small utility that reveals the password stored by Microsoft Remote Desktop Connection utility inside the .rdp files.
        // Reference: https://www.nirsoft.net/utils/remote_desktop_password.html
        $string6 = ">Remote Desktop PassView<" nocase ascii wide
        // Description: RemoteDesktopPassView is a small utility that reveals the password stored by Microsoft Remote Desktop Connection utility inside the .rdp files.
        // Reference: https://www.nirsoft.net/utils/remote_desktop_password.html
        $string7 = "205818e10c13d2e51b4c0196ca30111276ca1107fc8e25a0992fe67879eab964" nocase ascii wide
        // Description: RemoteDesktopPassView is a small utility that reveals the password stored by Microsoft Remote Desktop Connection utility inside the .rdp files.
        // Reference: https://www.nirsoft.net/utils/remote_desktop_password.html
        $string8 = "528de69797c36423a1e6b64fa8b1825f354e6707f2ca3760d81a9f58d69d58bb" nocase ascii wide
        // Description: RemoteDesktopPassView is a small utility that reveals the password stored by Microsoft Remote Desktop Connection utility inside the .rdp files.
        // Reference: https://www.nirsoft.net/utils/remote_desktop_password.html
        $string9 = /RemoteDesktopPassView\.zip/ nocase ascii wide
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
