rule MaliciousMacroMSBuild
{
    meta:
        description = "Detection patterns for the tool 'MaliciousMacroMSBuild' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "MaliciousMacroMSBuild"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Generates Malicious Macro and Execute Powershell or Shellcode via MSBuild Application Whitelisting Bypass.
        // Reference: https://github.com/infosecn1nja/MaliciousMacroMSBuild
        $string1 = /\sm3\-gen\.py\s/ nocase ascii wide
        // Description: Generates Malicious Macro and Execute Powershell or Shellcode via MSBuild Application Whitelisting Bypass.
        // Reference: https://github.com/infosecn1nja/MaliciousMacroMSBuild
        $string2 = /\s\-p\spowershell\s\-i\s.{0,1000}\.ps1\s\-o\s.{0,1000}\.vba/ nocase ascii wide
        // Description: Generates Malicious Macro and Execute Powershell or Shellcode via MSBuild Application Whitelisting Bypass.
        // Reference: https://github.com/infosecn1nja/MaliciousMacroMSBuild
        $string3 = /\s\-p\sshellcode\s\-i\s.{0,1000}\.bin\s\-o\s.{0,1000}\.vba/ nocase ascii wide
        // Description: Generates Malicious Macro and Execute Powershell or Shellcode via MSBuild Application Whitelisting Bypass.
        // Reference: https://github.com/infosecn1nja/MaliciousMacroMSBuild
        $string4 = /\/m3\-gen\.py\s/ nocase ascii wide
        // Description: Generates Malicious Macro and Execute Powershell or Shellcode via MSBuild Application Whitelisting Bypass.
        // Reference: https://github.com/infosecn1nja/MaliciousMacroMSBuild
        $string5 = /\/MaliciousMacroMSBuild/ nocase ascii wide
        // Description: Generates Malicious Macro and Execute Powershell or Shellcode via MSBuild Application Whitelisting Bypass.
        // Reference: https://github.com/infosecn1nja/MaliciousMacroMSBuild
        $string6 = /\\m3\-gen\.py/ nocase ascii wide
        // Description: Generates Malicious Macro and Execute Powershell or Shellcode via MSBuild Application Whitelisting Bypass.
        // Reference: https://github.com/infosecn1nja/MaliciousMacroMSBuild
        $string7 = /MaliciousMacroMSBuild\-master/ nocase ascii wide

    condition:
        any of them
}
