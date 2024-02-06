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
        $string1 = /\s\-Ix64\s.{0,1000}\.bin\s\-Ix86\s.{0,1000}\.bin\s\-P\sInject\s\-O\s.{0,1000}\.png\s\-stageless/ nocase ascii wide
        // Description: Ivy is a payload creation framework for the execution of arbitrary VBA (macro) source code directly in memory
        // Reference: https://github.com/optiv/Ivy
        $string2 = /\s\-Ix64\s.{0,1000}\.bin\s\-Ix86\s.{0,1000}\.bin\s\-P\sLocal\s\-O\s.{0,1000}\.hta\s\-url\shttp\:.{0,1000}\s\-delivery\shta\s\-stageless/ nocase ascii wide
        // Description: Ivy is a payload creation framework for the execution of arbitrary VBA (macro) source code directly in memory
        // Reference: https://github.com/optiv/Ivy
        $string3 = /\s\-Ix64\s.{0,1000}\.bin\s\-Ix86\s.{0,1000}\.bin\s\-P\sLocal\s\-O\s.{0,1000}\.js\s\-url\shttp.{0,1000}\s\-delivery\sbits\s\-stageless/ nocase ascii wide
        // Description: Ivy is a payload creation framework for the execution of arbitrary VBA (macro) source code directly in memory
        // Reference: https://github.com/optiv/Ivy
        $string4 = /\s\-Ix64\s.{0,1000}\.bin\s\-Ix86\s.{0,1000}\.bin\s\-P\sLocal\s\-O\s.{0,1000}\.txt\s\-url\shttp.{0,1000}\s\-delivery\smacro\s\-stageless/ nocase ascii wide
        // Description: Ivy is a payload creation framework for the execution of arbitrary VBA (macro) source code directly in memory
        // Reference: https://github.com/optiv/Ivy
        $string5 = /\s\-Ix64\s.{0,1000}\.bin\s\-Ix86\s.{0,1000}\.bin\s\-P\sLocal\s\-O\s.{0,1000}\.xsl\s\-url\shttp.{0,1000}\s\-delivery\sxsl\s\-stageless/ nocase ascii wide
        // Description: Ivy is a payload creation framework for the execution of arbitrary VBA (macro) source code directly in memory
        // Reference: https://github.com/optiv/Ivy
        $string6 = /\s\-Ix64\s.{0,1000}\.c\s\-Ix86\s.{0,1000}\.c\s\-P\sLocal\s\-O\s.{0,1000}\.js/ nocase ascii wide
        // Description: Ivy is a payload creation framework for the execution of arbitrary VBA (macro) source code directly in memory
        // Reference: https://github.com/optiv/Ivy
        $string7 = /\s\-Ix64\s.{0,1000}\.vba\s\-Ix86\s.{0,1000}\.vba\s\-P\sInject\s\-O\s/ nocase ascii wide
        // Description: Ivy is a payload creation framework for the execution of arbitrary VBA (macro) source code directly in memory
        // Reference: https://github.com/optiv/Ivy
        $string8 = /\s\-stageless\s\-Ix64\s.{0,1000}\.bin\s\-Ix86\s.{0,1000}\.bin\s\-P\sInject\s\-O\s.{0,1000}\.js/ nocase ascii wide
        // Description: Ivy is a payload creation framework for the execution of arbitrary VBA (macro) source code directly in memory
        // Reference: https://github.com/optiv/Ivy
        $string9 = /\s\-stageless\s\-Ix64\s.{0,1000}\.bin\s\-Ix86\s.{0,1000}\.bin\s\-P\sInject\s\-process64\s.{0,1000}\.exe\s\-O\s.{0,1000}\.js/ nocase ascii wide
        // Description: Ivy is a payload creation framework for the execution of arbitrary VBA (macro) source code directly in memory
        // Reference: https://github.com/optiv/Ivy
        $string10 = /\s\-stageless\s\-Ix64\s.{0,1000}\.bin\s\-Ix86\s.{0,1000}\.bin\s\-P\sInject\s\-unhook\s\-O\s.{0,1000}\.js/ nocase ascii wide
        // Description: Ivy is a payload creation framework for the execution of arbitrary VBA (macro) source code directly in memory
        // Reference: https://github.com/optiv/Ivy
        $string11 = /\s\-stageless\s\-Ix64\s.{0,1000}\.bin\s\-Ix86\s.{0,1000}\.bin\s\-P\sLocal\s\-O\s.{0,1000}\.js/ nocase ascii wide
        // Description: Ivy is a payload creation framework for the execution of arbitrary VBA (macro) source code directly in memory
        // Reference: https://github.com/optiv/Ivy
        $string12 = /\s\-stageless\s\-Ix64\s.{0,1000}\.bin\s\-Ix86\s.{0,1000}\.bin\s\-P\sLocal\s\-unhook\s\-O\s.{0,1000}\.js/ nocase ascii wide
        // Description: Ivy is a payload creation framework for the execution of arbitrary VBA (macro) source code directly in memory
        // Reference: https://github.com/optiv/Ivy
        $string13 = /\.\/Ivy\s\-/ nocase ascii wide
        // Description: Ivy is a payload creation framework for the execution of arbitrary VBA (macro) source code directly in memory
        // Reference: https://github.com/optiv/Ivy
        $string14 = /\/Ivy\/Cryptor/ nocase ascii wide
        // Description: Ivy is a payload creation framework for the execution of arbitrary VBA (macro) source code directly in memory
        // Reference: https://github.com/optiv/Ivy
        $string15 = /\/Ivy\/Loader\// nocase ascii wide
        // Description: Ivy is a payload creation framework for the execution of arbitrary VBA (macro) source code directly in memory
        // Reference: https://github.com/optiv/Ivy
        $string16 = /\\Ivy\\Cryptor/ nocase ascii wide
        // Description: Ivy is a payload creation framework for the execution of arbitrary VBA (macro) source code directly in memory
        // Reference: https://github.com/optiv/Ivy
        $string17 = /\\Ivy\\Loader\\/ nocase ascii wide
        // Description: Ivy is a payload creation framework for the execution of arbitrary VBA (macro) source code directly in memory
        // Reference: https://github.com/optiv/Ivy
        $string18 = /go\sbuild\sIvy\.go/ nocase ascii wide
        // Description: Ivy is a payload creation framework for the execution of arbitrary VBA (macro) source code directly in memory
        // Reference: https://github.com/optiv/Ivy
        $string19 = /Ivy_1.{0,1000}_darwin_amd64/ nocase ascii wide
        // Description: Ivy is a payload creation framework for the execution of arbitrary VBA (macro) source code directly in memory
        // Reference: https://github.com/optiv/Ivy
        $string20 = /Ivy_1.{0,1000}_linux_amd64/ nocase ascii wide
        // Description: Ivy is a payload creation framework for the execution of arbitrary VBA (macro) source code directly in memory
        // Reference: https://github.com/optiv/Ivy
        $string21 = /Ivy_1.{0,1000}_windows_amd64\.exe/ nocase ascii wide
        // Description: Ivy is a payload creation framework for the execution of arbitrary VBA (macro) source code directly in memory
        // Reference: https://github.com/optiv/Ivy
        $string22 = /Ivy\-main\.zip/ nocase ascii wide
        // Description: Ivy is a payload creation framework for the execution of arbitrary VBA (macro) source code directly in memory
        // Reference: https://github.com/optiv/Ivy
        $string23 = /optiv\/Ivy\.git/ nocase ascii wide

    condition:
        any of them
}
