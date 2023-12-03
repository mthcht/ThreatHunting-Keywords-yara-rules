rule ysoserial_net
{
    meta:
        description = "Detection patterns for the tool 'ysoserial.net' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ysoserial.net"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Deserialization payload generator for a variety of .NET formatters
        // Reference: https://github.com/pwntester/ysoserial.net
        $string1 = /.{0,1000}\s\-c\s.{0,1000}ExploitClass\.cs.{0,1000}System\.dll.{0,1000}/ nocase ascii wide
        // Description: Deserialization payload generator for a variety of .NET formatters
        // Reference: https://github.com/pwntester/ysoserial.net
        $string2 = /.{0,1000}\s\-\-cve\=.{0,1000}\s\-\-command.{0,1000}/ nocase ascii wide
        // Description: Deserialization payload generator for a variety of .NET formatters
        // Reference: https://github.com/pwntester/ysoserial.net
        $string3 = /.{0,1000}\s\-g\sActivitySurrogateSelector.{0,1000}/ nocase ascii wide
        // Description: Deserialization payload generator for a variety of .NET formatters
        // Reference: https://github.com/pwntester/ysoserial.net
        $string4 = /.{0,1000}\s\-g\sClaimsPrincipal\s.{0,1000}/ nocase ascii wide
        // Description: Deserialization payload generator for a variety of .NET formatters
        // Reference: https://github.com/pwntester/ysoserial.net
        $string5 = /.{0,1000}\s\-g\sPSObject\s.{0,1000}/ nocase ascii wide
        // Description: Deserialization payload generator for a variety of .NET formatters
        // Reference: https://github.com/pwntester/ysoserial.net
        $string6 = /.{0,1000}\s\-g\sTextFormattingRunProperties\s.{0,1000}/ nocase ascii wide
        // Description: Deserialization payload generator for a variety of .NET formatters
        // Reference: https://github.com/pwntester/ysoserial.net
        $string7 = /.{0,1000}\s\-\-gadget\sActivitySurrogateSelector.{0,1000}/ nocase ascii wide
        // Description: Deserialization payload generator for a variety of .NET formatters
        // Reference: https://github.com/pwntester/ysoserial.net
        $string8 = /.{0,1000}\s\-\-gadget\sClaimsPrincipal\s.{0,1000}/ nocase ascii wide
        // Description: Deserialization payload generator for a variety of .NET formatters
        // Reference: https://github.com/pwntester/ysoserial.net
        $string9 = /.{0,1000}\s\-\-gadget\sPSObject\s.{0,1000}/ nocase ascii wide
        // Description: Deserialization payload generator for a variety of .NET formatters
        // Reference: https://github.com/pwntester/ysoserial.net
        $string10 = /.{0,1000}\s\-m\srun_command\s\-c\s.{0,1000}\.exe.{0,1000}/ nocase ascii wide
        // Description: Deserialization payload generator for a variety of .NET formatters
        // Reference: https://github.com/pwntester/ysoserial.net
        $string11 = /.{0,1000}\s\-p\sActivatorUrl.{0,1000}/ nocase ascii wide
        // Description: Deserialization payload generator for a variety of .NET formatters
        // Reference: https://github.com/pwntester/ysoserial.net
        $string12 = /.{0,1000}\s\-p\sAltserialization.{0,1000}/ nocase ascii wide
        // Description: Deserialization payload generator for a variety of .NET formatters
        // Reference: https://github.com/pwntester/ysoserial.net
        $string13 = /.{0,1000}\s\-p\sDotNetNuke.{0,1000}/ nocase ascii wide
        // Description: Deserialization payload generator for a variety of .NET formatters
        // Reference: https://github.com/pwntester/ysoserial.net
        $string14 = /.{0,1000}\s\-p\sSessionSecurityTokenHandler.{0,1000}/ nocase ascii wide
        // Description: Deserialization payload generator for a variety of .NET formatters
        // Reference: https://github.com/pwntester/ysoserial.net
        $string15 = /.{0,1000}\s\-p\sTransactionManagerReenlist.{0,1000}/ nocase ascii wide
        // Description: Deserialization payload generator for a variety of .NET formatters
        // Reference: https://github.com/pwntester/ysoserial.net
        $string16 = /.{0,1000}\/ghostfile\.aspx.{0,1000}/ nocase ascii wide
        // Description: Deserialization payload generator for a variety of .NET formatters
        // Reference: https://github.com/pwntester/ysoserial.net
        $string17 = /.{0,1000}\/ysoserial\/.{0,1000}/ nocase ascii wide
        // Description: Deserialization payload generator for a variety of .NET formatters
        // Reference: https://github.com/pwntester/ysoserial.net
        $string18 = /.{0,1000}\\windows\\temp\\ncat\.exe\s\-nv\s.{0,1000}/ nocase ascii wide
        // Description: Deserialization payload generator for a variety of .NET formatters
        // Reference: https://github.com/pwntester/ysoserial.net
        $string19 = /.{0,1000}\\ysoserial\\.{0,1000}/ nocase ascii wide
        // Description: Deserialization payload generator for a variety of .NET formatters
        // Reference: https://github.com/pwntester/ysoserial.net
        $string20 = /.{0,1000}echo\s123\s\>\sc:\\windows\\temp\\test\.txt.{0,1000}/ nocase ascii wide
        // Description: Deserialization payload generator for a variety of .NET formatters
        // Reference: https://github.com/pwntester/ysoserial.net
        $string21 = /.{0,1000}\-f\sBinaryFormatter\s\-g\sPSObject\s\-o\sbase64\s\-c\s.{0,1000}/ nocase ascii wide
        // Description: Deserialization payload generator for a variety of .NET formatters
        // Reference: https://github.com/pwntester/ysoserial.net
        $string22 = /.{0,1000}\-f\sJson\.Net\s\-g\sObjectDataProvider\s\-o\sraw\s\-c\s.{0,1000}/ nocase ascii wide
        // Description: Deserialization payload generator for a variety of .NET formatters
        // Reference: https://github.com/pwntester/ysoserial.net
        $string23 = /.{0,1000}fakepath31337.{0,1000}/ nocase ascii wide
        // Description: Deserialization payload generator for a variety of .NET formatters
        // Reference: https://github.com/pwntester/ysoserial.net
        $string24 = /.{0,1000}GhostWebShell\.cs.{0,1000}/ nocase ascii wide
        // Description: Deserialization payload generator for a variety of .NET formatters
        // Reference: https://github.com/pwntester/ysoserial.net
        $string25 = /.{0,1000}MessageBox\.Show.{0,1000}Pwned.{0,1000}/ nocase ascii wide
        // Description: Deserialization payload generator for a variety of .NET formatters
        // Reference: https://github.com/pwntester/ysoserial.net
        $string26 = /.{0,1000}ModifiedVulnerableBinaryFormatters\\info\.txt.{0,1000}/ nocase ascii wide
        // Description: Deserialization payload generator for a variety of .NET formatters
        // Reference: https://github.com/pwntester/ysoserial.net
        $string27 = /.{0,1000}PCVAIExhbmd1YWdlPSJDIyIlPgpUaGlzIGlzIHRoZSBhdHRhY2tlcidzIGZpbGUgPGJyLz4KUnVubmluZyBvbiB0aGUgc2VydmVyIGlmIGA8JT0xMzM4LTElPmAgaXMgMTMzNy4.{0,1000}/ nocase ascii wide
        // Description: Deserialization payload generator for a variety of .NET formatters
        // Reference: https://github.com/pwntester/ysoserial.net
        $string28 = /.{0,1000}TestConsoleApp_YSONET.{0,1000}/ nocase ascii wide
        // Description: Deserialization payload generator for a variety of .NET formatters
        // Reference: https://github.com/pwntester/ysoserial.net
        $string29 = /.{0,1000}X\-YSOSERIAL\-NET.{0,1000}/ nocase ascii wide
        // Description: Deserialization payload generator for a variety of .NET formatters
        // Reference: https://github.com/pwntester/ysoserial.net
        $string30 = /.{0,1000}ysoserial\s\-.{0,1000}/ nocase ascii wide
        // Description: Deserialization payload generator for a variety of .NET formatters
        // Reference: https://github.com/pwntester/ysoserial.net
        $string31 = /.{0,1000}ysoserial\-.{0,1000}\.zip/ nocase ascii wide
        // Description: Deserialization payload generator for a variety of .NET formatters
        // Reference: https://github.com/pwntester/ysoserial.net
        $string32 = /.{0,1000}ysoserial\.exe\s.{0,1000}/ nocase ascii wide
        // Description: Deserialization payload generator for a variety of .NET formatters
        // Reference: https://github.com/pwntester/ysoserial.net
        $string33 = /.{0,1000}ysoserial\.net.{0,1000}/ nocase ascii wide
        // Description: Deserialization payload generator for a variety of .NET formatters
        // Reference: https://github.com/pwntester/ysoserial.net
        $string34 = /.{0,1000}ysoserial\.sln.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
