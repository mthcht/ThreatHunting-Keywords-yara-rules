rule ROADtools
{
    meta:
        description = "Detection patterns for the tool 'ROADtools' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ROADtools"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A collection of Azure AD tools for offensive and defensive security purposes
        // Reference: https://github.com/dirkjanm/ROADtools
        $string1 = /\sauth\s\-\-prt\s.{0,100}\s\-\-prt\-sessionkey\s/ nocase ascii wide
        // Description: A collection of Azure AD tools for offensive and defensive security purposes
        // Reference: https://github.com/dirkjanm/ROADtools
        $string2 = /\/ROADtools\// nocase ascii wide
        // Description: A collection of Azure AD tools for offensive and defensive security purposes
        // Reference: https://github.com/dirkjanm/ROADtools
        $string3 = /\\ROADtools\\/ nocase ascii wide
        // Description: A collection of Azure AD tools for offensive and defensive security purposes
        // Reference: https://github.com/dirkjanm/ROADtools
        $string4 = /1e2136c0b4bef6f7a9de7cd1d57d2c5f3dae7f90116b50454db495970d0fe251/ nocase ascii wide
        // Description: A collection of Azure AD tools for offensive and defensive security purposes
        // Reference: https://github.com/dirkjanm/ROADtools
        $string5 = /dirkjan\@outsidersecurity\.nl/ nocase ascii wide
        // Description: A collection of Azure AD tools for offensive and defensive security purposes
        // Reference: https://github.com/dirkjanm/ROADtools
        $string6 = /install\s.{0,100}\sroadrecon/ nocase ascii wide
        // Description: A collection of Azure AD tools for offensive and defensive security purposes
        // Reference: https://github.com/dirkjanm/ROADtools
        $string7 = /pip\sinstall\sroadlib/ nocase ascii wide
        // Description: A collection of Azure AD tools for offensive and defensive security purposes
        // Reference: https://github.com/dirkjanm/ROADtools
        $string8 = /pip\sinstall\sroadrecon/ nocase ascii wide
        // Description: A collection of Azure AD tools for offensive and defensive security purposes
        // Reference: https://github.com/dirkjanm/ROADtools
        $string9 = /pip\sinstall\sroadtx/ nocase ascii wide
        // Description: A collection of Azure AD tools for offensive and defensive security purposes
        // Reference: https://github.com/dirkjanm/ROADtools
        $string10 = /roadrecon\sauth\s/ nocase ascii wide
        // Description: A collection of Azure AD tools for offensive and defensive security purposes
        // Reference: https://github.com/dirkjanm/ROADtools
        $string11 = /roadrecon\sdump\s/ nocase ascii wide
        // Description: A collection of Azure AD tools for offensive and defensive security purposes
        // Reference: https://github.com/dirkjanm/ROADtools
        $string12 = /roadrecon\sgather\s/ nocase ascii wide
        // Description: A collection of Azure AD tools for offensive and defensive security purposes
        // Reference: https://github.com/dirkjanm/ROADtools
        $string13 = /roadrecon\splugin\s/ nocase ascii wide
        // Description: A collection of Azure AD tools for offensive and defensive security purposes
        // Reference: https://github.com/dirkjanm/ROADtools
        $string14 = /roadrecon.{0,100}gather\.py/ nocase ascii wide
        // Description: A collection of Azure AD tools for offensive and defensive security purposes
        // Reference: https://github.com/dirkjanm/ROADtools
        $string15 = /roadrecon\.db/ nocase ascii wide
        // Description: A collection of Azure AD tools for offensive and defensive security purposes
        // Reference: https://github.com/dirkjanm/ROADtools
        $string16 = /roadrecon\/frontend/ nocase ascii wide
        // Description: A collection of Azure AD tools for offensive and defensive security purposes
        // Reference: https://github.com/dirkjanm/ROADtools
        $string17 = /ROADtools\.git/ nocase ascii wide
        // Description: A collection of Azure AD tools for offensive and defensive security purposes
        // Reference: https://github.com/dirkjanm/ROADtools
        $string18 = /roadtools\.roadlib\.auth/ nocase ascii wide
        // Description: A collection of Azure AD tools for offensive and defensive security purposes
        // Reference: https://github.com/dirkjanm/ROADtools
        $string19 = /roadtools\.roadtx\.main\:main/ nocase ascii wide
        // Description: A collection of Azure AD tools for offensive and defensive security purposes
        // Reference: https://github.com/dirkjanm/ROADtools
        $string20 = /ROADtools\-master/ nocase ascii wide
        // Description: A collection of Azure AD tools for offensive and defensive security purposes
        // Reference: https://github.com/dirkjanm/ROADtools
        $string21 = /roadtx\sbrowserprtinject\s/ nocase ascii wide
        // Description: A collection of Azure AD tools for offensive and defensive security purposes
        // Reference: https://github.com/dirkjanm/ROADtools
        $string22 = /roadtx\sdevice\s\-a\sdelete\s/ nocase ascii wide
        // Description: A collection of Azure AD tools for offensive and defensive security purposes
        // Reference: https://github.com/dirkjanm/ROADtools
        $string23 = /roadtx\sgetscope\s\-s/ nocase ascii wide
        // Description: A collection of Azure AD tools for offensive and defensive security purposes
        // Reference: https://github.com/dirkjanm/ROADtools
        $string24 = /roadtx\sgettokens\s\-u\s/ nocase ascii wide
        // Description: A collection of Azure AD tools for offensive and defensive security purposes
        // Reference: https://github.com/dirkjanm/ROADtools
        $string25 = /roadtx\sinteractiveauth\s\-c\s/ nocase ascii wide
        // Description: A collection of Azure AD tools for offensive and defensive security purposes
        // Reference: https://github.com/dirkjanm/ROADtools
        $string26 = /roadtx\skeepassauth\s\-/ nocase ascii wide
        // Description: A collection of Azure AD tools for offensive and defensive security purposes
        // Reference: https://github.com/dirkjanm/ROADtools
        $string27 = /roadtx\sprt\s\-u\s.{0,100}\-\-key\-pem\s/ nocase ascii wide
        // Description: A collection of Azure AD tools for offensive and defensive security purposes
        // Reference: https://github.com/dirkjanm/ROADtools
        $string28 = /roadtx\sprtauth\s\-/ nocase ascii wide
        // Description: A collection of Azure AD tools for offensive and defensive security purposes
        // Reference: https://github.com/dirkjanm/ROADtools
        $string29 = /roadtx\srefreshtokento\s\-/ nocase ascii wide
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
