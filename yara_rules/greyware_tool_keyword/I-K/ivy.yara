rule ivy
{
    meta:
        description = "Detection patterns for the tool 'ivy' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ivy"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Ivy is a payload creation framework for the execution of arbitrary VBA (macro) source code directly in memory
        // Reference: https://github.com/optiv/Ivy
        $string1 = /.{0,1000}\s\-Ix64\s.{0,1000}\.bin\s\-Ix86\s.{0,1000}\.bin\s\-P\sInject\s\-O\s.{0,1000}\.png\s\-stageless.{0,1000}/ nocase ascii wide
        // Description: Ivy is a payload creation framework for the execution of arbitrary VBA (macro) source code directly in memory
        // Reference: https://github.com/optiv/Ivy
        $string2 = /.{0,1000}\s\-Ix64\s.{0,1000}\.bin\s\-Ix86\s.{0,1000}\.bin\s\-P\sLocal\s\-O\s.{0,1000}\.hta\s\-url\shttp:.{0,1000}\s\-delivery\shta\s\-stageless.{0,1000}/ nocase ascii wide
        // Description: Ivy is a payload creation framework for the execution of arbitrary VBA (macro) source code directly in memory
        // Reference: https://github.com/optiv/Ivy
        $string3 = /.{0,1000}\s\-Ix64\s.{0,1000}\.bin\s\-Ix86\s.{0,1000}\.bin\s\-P\sLocal\s\-O\s.{0,1000}\.js\s\-url\shttp.{0,1000}\s\-delivery\sbits\s\-stageless.{0,1000}/ nocase ascii wide
        // Description: Ivy is a payload creation framework for the execution of arbitrary VBA (macro) source code directly in memory
        // Reference: https://github.com/optiv/Ivy
        $string4 = /.{0,1000}\s\-Ix64\s.{0,1000}\.bin\s\-Ix86\s.{0,1000}\.bin\s\-P\sLocal\s\-O\s.{0,1000}\.txt\s\-url\shttp.{0,1000}\s\-delivery\smacro\s\-stageless.{0,1000}/ nocase ascii wide
        // Description: Ivy is a payload creation framework for the execution of arbitrary VBA (macro) source code directly in memory
        // Reference: https://github.com/optiv/Ivy
        $string5 = /.{0,1000}\s\-Ix64\s.{0,1000}\.bin\s\-Ix86\s.{0,1000}\.bin\s\-P\sLocal\s\-O\s.{0,1000}\.xsl\s\-url\shttp.{0,1000}\s\-delivery\sxsl\s\-stageless.{0,1000}/ nocase ascii wide
        // Description: Ivy is a payload creation framework for the execution of arbitrary VBA (macro) source code directly in memory
        // Reference: https://github.com/optiv/Ivy
        $string6 = /.{0,1000}\s\-Ix64\s.{0,1000}\.c\s\-Ix86\s.{0,1000}\.c\s\-P\sLocal\s\-O\s.{0,1000}\.js.{0,1000}/ nocase ascii wide
        // Description: Ivy is a payload creation framework for the execution of arbitrary VBA (macro) source code directly in memory
        // Reference: https://github.com/optiv/Ivy
        $string7 = /.{0,1000}\s\-Ix64\s.{0,1000}\.vba\s\-Ix86\s.{0,1000}\.vba\s\-P\sInject\s\-O\s.{0,1000}/ nocase ascii wide
        // Description: Ivy is a payload creation framework for the execution of arbitrary VBA (macro) source code directly in memory
        // Reference: https://github.com/optiv/Ivy
        $string8 = /.{0,1000}\s\-stageless\s\-Ix64\s.{0,1000}\.bin\s\-Ix86\s.{0,1000}\.bin\s\-P\sInject\s\-O\s.{0,1000}\.js.{0,1000}/ nocase ascii wide
        // Description: Ivy is a payload creation framework for the execution of arbitrary VBA (macro) source code directly in memory
        // Reference: https://github.com/optiv/Ivy
        $string9 = /.{0,1000}\s\-stageless\s\-Ix64\s.{0,1000}\.bin\s\-Ix86\s.{0,1000}\.bin\s\-P\sInject\s\-process64\s.{0,1000}\.exe\s\-O\s.{0,1000}\.js.{0,1000}/ nocase ascii wide
        // Description: Ivy is a payload creation framework for the execution of arbitrary VBA (macro) source code directly in memory
        // Reference: https://github.com/optiv/Ivy
        $string10 = /.{0,1000}\s\-stageless\s\-Ix64\s.{0,1000}\.bin\s\-Ix86\s.{0,1000}\.bin\s\-P\sInject\s\-unhook\s\-O\s.{0,1000}\.js.{0,1000}/ nocase ascii wide
        // Description: Ivy is a payload creation framework for the execution of arbitrary VBA (macro) source code directly in memory
        // Reference: https://github.com/optiv/Ivy
        $string11 = /.{0,1000}\s\-stageless\s\-Ix64\s.{0,1000}\.bin\s\-Ix86\s.{0,1000}\.bin\s\-P\sLocal\s\-O\s.{0,1000}\.js.{0,1000}/ nocase ascii wide
        // Description: Ivy is a payload creation framework for the execution of arbitrary VBA (macro) source code directly in memory
        // Reference: https://github.com/optiv/Ivy
        $string12 = /.{0,1000}\s\-stageless\s\-Ix64\s.{0,1000}\.bin\s\-Ix86\s.{0,1000}\.bin\s\-P\sLocal\s\-unhook\s\-O\s.{0,1000}\.js.{0,1000}/ nocase ascii wide
        // Description: Ivy is a payload creation framework for the execution of arbitrary VBA (macro) source code directly in memory
        // Reference: https://github.com/optiv/Ivy
        $string13 = /.{0,1000}\.\/Ivy\s\-.{0,1000}/ nocase ascii wide
        // Description: Ivy is a payload creation framework for the execution of arbitrary VBA (macro) source code directly in memory
        // Reference: https://github.com/optiv/Ivy
        $string14 = /.{0,1000}\/Ivy\/Cryptor.{0,1000}/ nocase ascii wide
        // Description: Ivy is a payload creation framework for the execution of arbitrary VBA (macro) source code directly in memory
        // Reference: https://github.com/optiv/Ivy
        $string15 = /.{0,1000}\/Ivy\/Loader\/.{0,1000}/ nocase ascii wide
        // Description: Ivy is a payload creation framework for the execution of arbitrary VBA (macro) source code directly in memory
        // Reference: https://github.com/optiv/Ivy
        $string16 = /.{0,1000}\\Ivy\\Cryptor.{0,1000}/ nocase ascii wide
        // Description: Ivy is a payload creation framework for the execution of arbitrary VBA (macro) source code directly in memory
        // Reference: https://github.com/optiv/Ivy
        $string17 = /.{0,1000}\\Ivy\\Loader\\.{0,1000}/ nocase ascii wide
        // Description: Ivy is a payload creation framework for the execution of arbitrary VBA (macro) source code directly in memory
        // Reference: https://github.com/optiv/Ivy
        $string18 = /.{0,1000}go\sbuild\sIvy\.go.{0,1000}/ nocase ascii wide
        // Description: Ivy is a payload creation framework for the execution of arbitrary VBA (macro) source code directly in memory
        // Reference: https://github.com/optiv/Ivy
        $string19 = /.{0,1000}Ivy_1.{0,1000}_darwin_amd64.{0,1000}/ nocase ascii wide
        // Description: Ivy is a payload creation framework for the execution of arbitrary VBA (macro) source code directly in memory
        // Reference: https://github.com/optiv/Ivy
        $string20 = /.{0,1000}Ivy_1.{0,1000}_linux_amd64.{0,1000}/ nocase ascii wide
        // Description: Ivy is a payload creation framework for the execution of arbitrary VBA (macro) source code directly in memory
        // Reference: https://github.com/optiv/Ivy
        $string21 = /.{0,1000}Ivy_1.{0,1000}_windows_amd64\.exe.{0,1000}/ nocase ascii wide
        // Description: Ivy is a payload creation framework for the execution of arbitrary VBA (macro) source code directly in memory
        // Reference: https://github.com/optiv/Ivy
        $string22 = /.{0,1000}Ivy\-main\.zip.{0,1000}/ nocase ascii wide
        // Description: Ivy is a payload creation framework for the execution of arbitrary VBA (macro) source code directly in memory
        // Reference: https://github.com/optiv/Ivy
        $string23 = /.{0,1000}optiv\/Ivy\.git.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
