rule Macrome
{
    meta:
        description = "Detection patterns for the tool 'Macrome' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Macrome"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: An Excel Macro Document Reader/Writer for Red Teamers & Analysts. Blog posts describing what this tool actually does can be found https://malware.pizza/2020/05/12/evading-av-with-excel-macros-and-biff8-xls/ and https://malware.pizza/2020/06/19/further-evasion-in-the-forgotten-corners-of-ms-xls/
        // Reference: https://github.com/michaelweber/Macrome
        $string1 = /\sCharSubroutine\-Macro\.xls/ nocase ascii wide
        // Description: An Excel Macro Document Reader/Writer for Red Teamers & Analysts. Blog posts describing what this tool actually does can be found https://malware.pizza/2020/05/12/evading-av-with-excel-macros-and-biff8-xls/ and https://malware.pizza/2020/06/19/further-evasion-in-the-forgotten-corners-of-ms-xls/
        // Reference: https://github.com/michaelweber/Macrome
        $string2 = /\spopcalc\.bin\s/ nocase ascii wide
        // Description: An Excel Macro Document Reader/Writer for Red Teamers & Analysts. Blog posts describing what this tool actually does can be found https://malware.pizza/2020/05/12/evading-av-with-excel-macros-and-biff8-xls/ and https://malware.pizza/2020/06/19/further-evasion-in-the-forgotten-corners-of-ms-xls/
        // Reference: https://github.com/michaelweber/Macrome
        $string3 = /\spopcalc64\.bin\s/ nocase ascii wide
        // Description: An Excel Macro Document Reader/Writer for Red Teamers & Analysts. Blog posts describing what this tool actually does can be found https://malware.pizza/2020/05/12/evading-av-with-excel-macros-and-biff8-xls/ and https://malware.pizza/2020/06/19/further-evasion-in-the-forgotten-corners-of-ms-xls/
        // Reference: https://github.com/michaelweber/Macrome
        $string4 = /\/BaseNEncoder\.cs/ nocase ascii wide
        // Description: An Excel Macro Document Reader/Writer for Red Teamers & Analysts. Blog posts describing what this tool actually does can be found https://malware.pizza/2020/05/12/evading-av-with-excel-macros-and-biff8-xls/ and https://malware.pizza/2020/06/19/further-evasion-in-the-forgotten-corners-of-ms-xls/
        // Reference: https://github.com/michaelweber/Macrome
        $string5 = /\/BIFFRecordEncryption\.cs/ nocase ascii wide
        // Description: An Excel Macro Document Reader/Writer for Red Teamers & Analysts. Blog posts describing what this tool actually does can be found https://malware.pizza/2020/05/12/evading-av-with-excel-macros-and-biff8-xls/ and https://malware.pizza/2020/06/19/further-evasion-in-the-forgotten-corners-of-ms-xls/
        // Reference: https://github.com/michaelweber/Macrome
        $string6 = /\/ExcelDocWriter\.cs/ nocase ascii wide
        // Description: An Excel Macro Document Reader/Writer for Red Teamers & Analysts. Blog posts describing what this tool actually does can be found https://malware.pizza/2020/05/12/evading-av-with-excel-macros-and-biff8-xls/ and https://malware.pizza/2020/06/19/further-evasion-in-the-forgotten-corners-of-ms-xls/
        // Reference: https://github.com/michaelweber/Macrome
        $string7 = /\/MacroPatterns\.cs/ nocase ascii wide
        // Description: An Excel Macro Document Reader/Writer for Red Teamers & Analysts. Blog posts describing what this tool actually does can be found https://malware.pizza/2020/05/12/evading-av-with-excel-macros-and-biff8-xls/ and https://malware.pizza/2020/06/19/further-evasion-in-the-forgotten-corners-of-ms-xls/
        // Reference: https://github.com/michaelweber/Macrome
        $string8 = /\/michaelweber\/Macrome/ nocase ascii wide
        // Description: An Excel Macro Document Reader/Writer for Red Teamers & Analysts. Blog posts describing what this tool actually does can be found https://malware.pizza/2020/05/12/evading-av-with-excel-macros-and-biff8-xls/ and https://malware.pizza/2020/06/19/further-evasion-in-the-forgotten-corners-of-ms-xls/
        // Reference: https://github.com/michaelweber/Macrome
        $string9 = /\/RC4BinaryEncryption\.cs/ nocase ascii wide
        // Description: An Excel Macro Document Reader/Writer for Red Teamers & Analysts. Blog posts describing what this tool actually does can be found https://malware.pizza/2020/05/12/evading-av-with-excel-macros-and-biff8-xls/ and https://malware.pizza/2020/06/19/further-evasion-in-the-forgotten-corners-of-ms-xls/
        // Reference: https://github.com/michaelweber/Macrome
        $string10 = /\/XorObfuscation\.cs/ nocase ascii wide
        // Description: An Excel Macro Document Reader/Writer for Red Teamers & Analysts. Blog posts describing what this tool actually does can be found https://malware.pizza/2020/05/12/evading-av-with-excel-macros-and-biff8-xls/ and https://malware.pizza/2020/06/19/further-evasion-in-the-forgotten-corners-of-ms-xls/
        // Reference: https://github.com/michaelweber/Macrome
        $string11 = /b2xtranslator\.xls\.csproj/ nocase ascii wide
        // Description: An Excel Macro Document Reader/Writer for Red Teamers & Analysts. Blog posts describing what this tool actually does can be found https://malware.pizza/2020/05/12/evading-av-with-excel-macros-and-biff8-xls/ and https://malware.pizza/2020/06/19/further-evasion-in-the-forgotten-corners-of-ms-xls/
        // Reference: https://github.com/michaelweber/Macrome
        $string12 = /decoy_document\.xls/ nocase ascii wide
        // Description: An Excel Macro Document Reader/Writer for Red Teamers & Analysts. Blog posts describing what this tool actually does can be found https://malware.pizza/2020/05/12/evading-av-with-excel-macros-and-biff8-xls/ and https://malware.pizza/2020/06/19/further-evasion-in-the-forgotten-corners-of-ms-xls/
        // Reference: https://github.com/michaelweber/Macrome
        $string13 = /Macrome\s.{0,1000}\-\-decoy\-document/ nocase ascii wide
        // Description: An Excel Macro Document Reader/Writer for Red Teamers & Analysts. Blog posts describing what this tool actually does can be found https://malware.pizza/2020/05/12/evading-av-with-excel-macros-and-biff8-xls/ and https://malware.pizza/2020/06/19/further-evasion-in-the-forgotten-corners-of-ms-xls/
        // Reference: https://github.com/michaelweber/Macrome
        $string14 = /Macrome\s.{0,1000}\-\-payload/ nocase ascii wide
        // Description: An Excel Macro Document Reader/Writer for Red Teamers & Analysts. Blog posts describing what this tool actually does can be found https://malware.pizza/2020/05/12/evading-av-with-excel-macros-and-biff8-xls/ and https://malware.pizza/2020/06/19/further-evasion-in-the-forgotten-corners-of-ms-xls/
        // Reference: https://github.com/michaelweber/Macrome
        $string15 = /Macrome\sbuild/ nocase ascii wide
        // Description: An Excel Macro Document Reader/Writer for Red Teamers & Analysts. Blog posts describing what this tool actually does can be found https://malware.pizza/2020/05/12/evading-av-with-excel-macros-and-biff8-xls/ and https://malware.pizza/2020/06/19/further-evasion-in-the-forgotten-corners-of-ms-xls/
        // Reference: https://github.com/michaelweber/Macrome
        $string16 = /Macrome\.csproj/ nocase ascii wide
        // Description: An Excel Macro Document Reader/Writer for Red Teamers & Analysts. Blog posts describing what this tool actually does can be found https://malware.pizza/2020/05/12/evading-av-with-excel-macros-and-biff8-xls/ and https://malware.pizza/2020/06/19/further-evasion-in-the-forgotten-corners-of-ms-xls/
        // Reference: https://github.com/michaelweber/Macrome
        $string17 = /Macrome\.dll/ nocase ascii wide
        // Description: An Excel Macro Document Reader/Writer for Red Teamers & Analysts. Blog posts describing what this tool actually does can be found https://malware.pizza/2020/05/12/evading-av-with-excel-macros-and-biff8-xls/ and https://malware.pizza/2020/06/19/further-evasion-in-the-forgotten-corners-of-ms-xls/
        // Reference: https://github.com/michaelweber/Macrome
        $string18 = /Macrome\.sln/ nocase ascii wide
        // Description: An Excel Macro Document Reader/Writer for Red Teamers & Analysts. Blog posts describing what this tool actually does can be found https://malware.pizza/2020/05/12/evading-av-with-excel-macros-and-biff8-xls/ and https://malware.pizza/2020/06/19/further-evasion-in-the-forgotten-corners-of-ms-xls/
        // Reference: https://github.com/michaelweber/Macrome
        $string19 = /\-\-path\sdocToDump\.xls/ nocase ascii wide
        // Description: An Excel Macro Document Reader/Writer for Red Teamers & Analysts. Blog posts describing what this tool actually does can be found https://malware.pizza/2020/05/12/evading-av-with-excel-macros-and-biff8-xls/ and https://malware.pizza/2020/06/19/further-evasion-in-the-forgotten-corners-of-ms-xls/
        // Reference: https://github.com/michaelweber/Macrome
        $string20 = /\-\-payload\-type\sMacro/ nocase ascii wide
        // Description: An Excel Macro Document Reader/Writer for Red Teamers & Analysts. Blog posts describing what this tool actually does can be found https://malware.pizza/2020/05/12/evading-av-with-excel-macros-and-biff8-xls/ and https://malware.pizza/2020/06/19/further-evasion-in-the-forgotten-corners-of-ms-xls/
        // Reference: https://github.com/michaelweber/Macrome
        $string21 = /ReadyToPhish\.xls/ nocase ascii wide

    condition:
        any of them
}
