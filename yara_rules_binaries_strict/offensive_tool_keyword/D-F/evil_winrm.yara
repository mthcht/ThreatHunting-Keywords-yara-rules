rule evil_winrm
{
    meta:
        description = "Detection patterns for the tool 'evil-winrm' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "evil-winrm"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: This shell is the ultimate WinRM shell for hacking/pentesting.WinRM (Windows Remote Management) is the Microsoft implementation of WS-Management Protocol. A standard SOAP based protocol that allows hardware and operating systems from different vendors to interoperate. Microsoft included it in their Operating Systems in order to make life easier to system administrators.This program can be used on any Microsoft Windows Servers with this feature enabled (usually at port 5985). of course only if you have credentials and permissions to use it. So we can say that it could be used in a post-exploitation hacking/pentesting phase. The purpose of this program is to provide nice and easy-to-use features for hacking. It can be used with legitimate purposes by system administrators as well but the most of its features are focused on hacking/pentesting stuff.
        // Reference: https://github.com/Hackplayers/evil-winrm
        $string1 = /\sdownload\s.{0,100}\\NTDS\\NTDS\.dit/ nocase ascii wide
        // Description: This shell is the ultimate WinRM shell for hacking/pentesting.WinRM (Windows Remote Management) is the Microsoft implementation of WS-Management Protocol. A standard SOAP based protocol that allows hardware and operating systems from different vendors to interoperate. Microsoft included it in their Operating Systems in order to make life easier to system administrators.This program can be used on any Microsoft Windows Servers with this feature enabled (usually at port 5985). of course only if you have credentials and permissions to use it. So we can say that it could be used in a post-exploitation hacking/pentesting phase. The purpose of this program is to provide nice and easy-to-use features for hacking. It can be used with legitimate purposes by system administrators as well but the most of its features are focused on hacking/pentesting stuff.
        // Reference: https://github.com/Hackplayers/evil-winrm
        $string2 = /\sdownload\s.{0,100}\\Windows\\System32\\config\\SYSTEM/ nocase ascii wide
        // Description: This shell is the ultimate WinRM shell for hacking/pentesting.WinRM (Windows Remote Management) is the Microsoft implementation of WS-Management Protocol. A standard SOAP based protocol that allows hardware and operating systems from different vendors to interoperate. Microsoft included it in their Operating Systems in order to make life easier to system administrators.This program can be used on any Microsoft Windows Servers with this feature enabled (usually at port 5985). of course only if you have credentials and permissions to use it. So we can say that it could be used in a post-exploitation hacking/pentesting phase. The purpose of this program is to provide nice and easy-to-use features for hacking. It can be used with legitimate purposes by system administrators as well but the most of its features are focused on hacking/pentesting stuff.
        // Reference: https://github.com/Hackplayers/evil-winrm
        $string3 = /Bypass\-4MSI/ nocase ascii wide
        // Description: This shell is the ultimate WinRM shell for hacking/pentesting.WinRM (Windows Remote Management) is the Microsoft implementation of WS-Management Protocol. A standard SOAP based protocol that allows hardware and operating systems from different vendors to interoperate. Microsoft included it in their Operating Systems in order to make life easier to system administrators.This program can be used on any Microsoft Windows Servers with this feature enabled (usually at port 5985). of course only if you have credentials and permissions to use it. So we can say that it could be used in a post-exploitation hacking/pentesting phase. The purpose of this program is to provide nice and easy-to-use features for hacking. It can be used with legitimate purposes by system administrators as well but the most of its features are focused on hacking/pentesting stuff.
        // Reference: https://github.com/Hackplayers/evil-winrm
        $string4 = /cmd\s\/c\smklink\s\/d\s.{0,100}\sHarddiskVolumeShadowCopy1/ nocase ascii wide
        // Description: This shell is the ultimate WinRM shell for hacking/pentesting.WinRM (Windows Remote Management) is the Microsoft implementation of WS-Management Protocol. A standard SOAP based protocol that allows hardware and operating systems from different vendors to interoperate. Microsoft included it in their Operating Systems in order to make life easier to system administrators.This program can be used on any Microsoft Windows Servers with this feature enabled (usually at port 5985). of course only if you have credentials and permissions to use it. So we can say that it could be used in a post-exploitation hacking/pentesting phase. The purpose of this program is to provide nice and easy-to-use features for hacking. It can be used with legitimate purposes by system administrators as well but the most of its features are focused on hacking/pentesting stuff.
        // Reference: https://github.com/Hackplayers/evil-winrm
        $string5 = /Dll\-Loader\s\-http\s\-path\s/ nocase ascii wide
        // Description: This shell is the ultimate WinRM shell for hacking/pentesting.WinRM (Windows Remote Management) is the Microsoft implementation of WS-Management Protocol. A standard SOAP based protocol that allows hardware and operating systems from different vendors to interoperate. Microsoft included it in their Operating Systems in order to make life easier to system administrators.This program can be used on any Microsoft Windows Servers with this feature enabled (usually at port 5985). of course only if you have credentials and permissions to use it. So we can say that it could be used in a post-exploitation hacking/pentesting phase. The purpose of this program is to provide nice and easy-to-use features for hacking. It can be used with legitimate purposes by system administrators as well but the most of its features are focused on hacking/pentesting stuff.
        // Reference: https://github.com/Hackplayers/evil-winrm
        $string6 = /Dll\-Loader\s\-local\s\-path/ nocase ascii wide
        // Description: This shell is the ultimate WinRM shell for hacking/pentesting.WinRM (Windows Remote Management) is the Microsoft implementation of WS-Management Protocol. A standard SOAP based protocol that allows hardware and operating systems from different vendors to interoperate. Microsoft included it in their Operating Systems in order to make life easier to system administrators.This program can be used on any Microsoft Windows Servers with this feature enabled (usually at port 5985). of course only if you have credentials and permissions to use it. So we can say that it could be used in a post-exploitation hacking/pentesting phase. The purpose of this program is to provide nice and easy-to-use features for hacking. It can be used with legitimate purposes by system administrators as well but the most of its features are focused on hacking/pentesting stuff.
        // Reference: https://github.com/Hackplayers/evil-winrm
        $string7 = /Dll\-Loader\s\-smb\s\-path\s/ nocase ascii wide
        // Description: This shell is the ultimate WinRM shell for hacking/pentesting.WinRM (Windows Remote Management) is the Microsoft implementation of WS-Management Protocol. A standard SOAP based protocol that allows hardware and operating systems from different vendors to interoperate. Microsoft included it in their Operating Systems in order to make life easier to system administrators.This program can be used on any Microsoft Windows Servers with this feature enabled (usually at port 5985). of course only if you have credentials and permissions to use it. So we can say that it could be used in a post-exploitation hacking/pentesting phase. The purpose of this program is to provide nice and easy-to-use features for hacking. It can be used with legitimate purposes by system administrators as well but the most of its features are focused on hacking/pentesting stuff.
        // Reference: https://github.com/Hackplayers/evil-winrm
        $string8 = /Donut\-Loader\s\-process_id/ nocase ascii wide
        // Description: This shell is the ultimate WinRM shell for hacking/pentesting.WinRM (Windows Remote Management) is the Microsoft implementation of WS-Management Protocol. A standard SOAP based protocol that allows hardware and operating systems from different vendors to interoperate. Microsoft included it in their Operating Systems in order to make life easier to system administrators.This program can be used on any Microsoft Windows Servers with this feature enabled (usually at port 5985). of course only if you have credentials and permissions to use it. So we can say that it could be used in a post-exploitation hacking/pentesting phase. The purpose of this program is to provide nice and easy-to-use features for hacking. It can be used with legitimate purposes by system administrators as well but the most of its features are focused on hacking/pentesting stuff.
        // Reference: https://github.com/Hackplayers/evil-winrm
        $string9 = /donut\-maker\.py\s\-i\s.{0,100}\.exe/ nocase ascii wide
        // Description: This shell is the ultimate WinRM shell for hacking/pentesting.WinRM (Windows Remote Management) is the Microsoft implementation of WS-Management Protocol. A standard SOAP based protocol that allows hardware and operating systems from different vendors to interoperate. Microsoft included it in their Operating Systems in order to make life easier to system administrators.This program can be used on any Microsoft Windows Servers with this feature enabled (usually at port 5985). of course only if you have credentials and permissions to use it. So we can say that it could be used in a post-exploitation hacking/pentesting phase. The purpose of this program is to provide nice and easy-to-use features for hacking. It can be used with legitimate purposes by system administrators as well but the most of its features are focused on hacking/pentesting stuff.
        // Reference: https://github.com/Hackplayers/evil-winrm
        $string10 = /download\s.{0,100}Roaming\\mRemoteNG\\confCons\.xml/ nocase ascii wide
        // Description: This shell is the ultimate WinRM shell for hacking/pentesting.WinRM (Windows Remote Management) is the Microsoft implementation of WS-Management Protocol. A standard SOAP based protocol that allows hardware and operating systems from different vendors to interoperate. Microsoft included it in their Operating Systems in order to make life easier to system administrators.This program can be used on any Microsoft Windows Servers with this feature enabled (usually at port 5985). of course only if you have credentials and permissions to use it. So we can say that it could be used in a post-exploitation hacking/pentesting phase. The purpose of this program is to provide nice and easy-to-use features for hacking. It can be used with legitimate purposes by system administrators as well but the most of its features are focused on hacking/pentesting stuff.
        // Reference: https://github.com/Hackplayers/evil-winrm
        $string11 = /evil\-winrm/ nocase ascii wide
        // Description: This shell is the ultimate WinRM shell for hacking/pentesting.WinRM (Windows Remote Management) is the Microsoft implementation of WS-Management Protocol. A standard SOAP based protocol that allows hardware and operating systems from different vendors to interoperate. Microsoft included it in their Operating Systems in order to make life easier to system administrators.This program can be used on any Microsoft Windows Servers with this feature enabled (usually at port 5985). of course only if you have credentials and permissions to use it. So we can say that it could be used in a post-exploitation hacking/pentesting phase. The purpose of this program is to provide nice and easy-to-use features for hacking. It can be used with legitimate purposes by system administrators as well but the most of its features are focused on hacking/pentesting stuff.
        // Reference: https://github.com/Hackplayers/evil-winrm
        $string12 = /Invoke\-Binary\s.{0,100}\.exe/ nocase ascii wide
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
