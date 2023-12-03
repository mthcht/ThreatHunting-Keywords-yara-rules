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
        $string1 = /.{0,1000}\sCharSubroutine\-Macro\.xls.{0,1000}/ nocase ascii wide
        // Description: An Excel Macro Document Reader/Writer for Red Teamers & Analysts. Blog posts describing what this tool actually does can be found https://malware.pizza/2020/05/12/evading-av-with-excel-macros-and-biff8-xls/ and https://malware.pizza/2020/06/19/further-evasion-in-the-forgotten-corners-of-ms-xls/
        // Reference: https://github.com/michaelweber/Macrome
        $string2 = /.{0,1000}\spopcalc\.bin\s.{0,1000}/ nocase ascii wide
        // Description: An Excel Macro Document Reader/Writer for Red Teamers & Analysts. Blog posts describing what this tool actually does can be found https://malware.pizza/2020/05/12/evading-av-with-excel-macros-and-biff8-xls/ and https://malware.pizza/2020/06/19/further-evasion-in-the-forgotten-corners-of-ms-xls/
        // Reference: https://github.com/michaelweber/Macrome
        $string3 = /.{0,1000}\spopcalc64\.bin\s.{0,1000}/ nocase ascii wide
        // Description: An Excel Macro Document Reader/Writer for Red Teamers & Analysts. Blog posts describing what this tool actually does can be found https://malware.pizza/2020/05/12/evading-av-with-excel-macros-and-biff8-xls/ and https://malware.pizza/2020/06/19/further-evasion-in-the-forgotten-corners-of-ms-xls/
        // Reference: https://github.com/michaelweber/Macrome
        $string4 = /.{0,1000}\/BaseNEncoder\.cs.{0,1000}/ nocase ascii wide
        // Description: An Excel Macro Document Reader/Writer for Red Teamers & Analysts. Blog posts describing what this tool actually does can be found https://malware.pizza/2020/05/12/evading-av-with-excel-macros-and-biff8-xls/ and https://malware.pizza/2020/06/19/further-evasion-in-the-forgotten-corners-of-ms-xls/
        // Reference: https://github.com/michaelweber/Macrome
        $string5 = /.{0,1000}\/BIFFRecordEncryption\.cs.{0,1000}/ nocase ascii wide
        // Description: An Excel Macro Document Reader/Writer for Red Teamers & Analysts. Blog posts describing what this tool actually does can be found https://malware.pizza/2020/05/12/evading-av-with-excel-macros-and-biff8-xls/ and https://malware.pizza/2020/06/19/further-evasion-in-the-forgotten-corners-of-ms-xls/
        // Reference: https://github.com/michaelweber/Macrome
        $string6 = /.{0,1000}\/ExcelDocWriter\.cs.{0,1000}/ nocase ascii wide
        // Description: An Excel Macro Document Reader/Writer for Red Teamers & Analysts. Blog posts describing what this tool actually does can be found https://malware.pizza/2020/05/12/evading-av-with-excel-macros-and-biff8-xls/ and https://malware.pizza/2020/06/19/further-evasion-in-the-forgotten-corners-of-ms-xls/
        // Reference: https://github.com/michaelweber/Macrome
        $string7 = /.{0,1000}\/MacroPatterns\.cs.{0,1000}/ nocase ascii wide
        // Description: An Excel Macro Document Reader/Writer for Red Teamers & Analysts. Blog posts describing what this tool actually does can be found https://malware.pizza/2020/05/12/evading-av-with-excel-macros-and-biff8-xls/ and https://malware.pizza/2020/06/19/further-evasion-in-the-forgotten-corners-of-ms-xls/
        // Reference: https://github.com/michaelweber/Macrome
        $string8 = /.{0,1000}\/michaelweber\/Macrome.{0,1000}/ nocase ascii wide
        // Description: An Excel Macro Document Reader/Writer for Red Teamers & Analysts. Blog posts describing what this tool actually does can be found https://malware.pizza/2020/05/12/evading-av-with-excel-macros-and-biff8-xls/ and https://malware.pizza/2020/06/19/further-evasion-in-the-forgotten-corners-of-ms-xls/
        // Reference: https://github.com/michaelweber/Macrome
        $string9 = /.{0,1000}\/RC4BinaryEncryption\.cs.{0,1000}/ nocase ascii wide
        // Description: An Excel Macro Document Reader/Writer for Red Teamers & Analysts. Blog posts describing what this tool actually does can be found https://malware.pizza/2020/05/12/evading-av-with-excel-macros-and-biff8-xls/ and https://malware.pizza/2020/06/19/further-evasion-in-the-forgotten-corners-of-ms-xls/
        // Reference: https://github.com/michaelweber/Macrome
        $string10 = /.{0,1000}\/XorObfuscation\.cs.{0,1000}/ nocase ascii wide
        // Description: An Excel Macro Document Reader/Writer for Red Teamers & Analysts. Blog posts describing what this tool actually does can be found https://malware.pizza/2020/05/12/evading-av-with-excel-macros-and-biff8-xls/ and https://malware.pizza/2020/06/19/further-evasion-in-the-forgotten-corners-of-ms-xls/
        // Reference: https://github.com/michaelweber/Macrome
        $string11 = /.{0,1000}b2xtranslator\.xls\.csproj.{0,1000}/ nocase ascii wide
        // Description: An Excel Macro Document Reader/Writer for Red Teamers & Analysts. Blog posts describing what this tool actually does can be found https://malware.pizza/2020/05/12/evading-av-with-excel-macros-and-biff8-xls/ and https://malware.pizza/2020/06/19/further-evasion-in-the-forgotten-corners-of-ms-xls/
        // Reference: https://github.com/michaelweber/Macrome
        $string12 = /.{0,1000}decoy_document\.xls.{0,1000}/ nocase ascii wide
        // Description: An Excel Macro Document Reader/Writer for Red Teamers & Analysts. Blog posts describing what this tool actually does can be found https://malware.pizza/2020/05/12/evading-av-with-excel-macros-and-biff8-xls/ and https://malware.pizza/2020/06/19/further-evasion-in-the-forgotten-corners-of-ms-xls/
        // Reference: https://github.com/michaelweber/Macrome
        $string13 = /.{0,1000}Macrome\s.{0,1000}\-\-decoy\-document.{0,1000}/ nocase ascii wide
        // Description: An Excel Macro Document Reader/Writer for Red Teamers & Analysts. Blog posts describing what this tool actually does can be found https://malware.pizza/2020/05/12/evading-av-with-excel-macros-and-biff8-xls/ and https://malware.pizza/2020/06/19/further-evasion-in-the-forgotten-corners-of-ms-xls/
        // Reference: https://github.com/michaelweber/Macrome
        $string14 = /.{0,1000}Macrome\s.{0,1000}\-\-payload.{0,1000}/ nocase ascii wide
        // Description: An Excel Macro Document Reader/Writer for Red Teamers & Analysts. Blog posts describing what this tool actually does can be found https://malware.pizza/2020/05/12/evading-av-with-excel-macros-and-biff8-xls/ and https://malware.pizza/2020/06/19/further-evasion-in-the-forgotten-corners-of-ms-xls/
        // Reference: https://github.com/michaelweber/Macrome
        $string15 = /.{0,1000}Macrome\sbuild.{0,1000}/ nocase ascii wide
        // Description: An Excel Macro Document Reader/Writer for Red Teamers & Analysts. Blog posts describing what this tool actually does can be found https://malware.pizza/2020/05/12/evading-av-with-excel-macros-and-biff8-xls/ and https://malware.pizza/2020/06/19/further-evasion-in-the-forgotten-corners-of-ms-xls/
        // Reference: https://github.com/michaelweber/Macrome
        $string16 = /.{0,1000}Macrome\.csproj.{0,1000}/ nocase ascii wide
        // Description: An Excel Macro Document Reader/Writer for Red Teamers & Analysts. Blog posts describing what this tool actually does can be found https://malware.pizza/2020/05/12/evading-av-with-excel-macros-and-biff8-xls/ and https://malware.pizza/2020/06/19/further-evasion-in-the-forgotten-corners-of-ms-xls/
        // Reference: https://github.com/michaelweber/Macrome
        $string17 = /.{0,1000}Macrome\.dll.{0,1000}/ nocase ascii wide
        // Description: An Excel Macro Document Reader/Writer for Red Teamers & Analysts. Blog posts describing what this tool actually does can be found https://malware.pizza/2020/05/12/evading-av-with-excel-macros-and-biff8-xls/ and https://malware.pizza/2020/06/19/further-evasion-in-the-forgotten-corners-of-ms-xls/
        // Reference: https://github.com/michaelweber/Macrome
        $string18 = /.{0,1000}Macrome\.sln.{0,1000}/ nocase ascii wide
        // Description: An Excel Macro Document Reader/Writer for Red Teamers & Analysts. Blog posts describing what this tool actually does can be found https://malware.pizza/2020/05/12/evading-av-with-excel-macros-and-biff8-xls/ and https://malware.pizza/2020/06/19/further-evasion-in-the-forgotten-corners-of-ms-xls/
        // Reference: https://github.com/michaelweber/Macrome
        $string19 = /.{0,1000}\-\-path\sdocToDump\.xls.{0,1000}/ nocase ascii wide
        // Description: An Excel Macro Document Reader/Writer for Red Teamers & Analysts. Blog posts describing what this tool actually does can be found https://malware.pizza/2020/05/12/evading-av-with-excel-macros-and-biff8-xls/ and https://malware.pizza/2020/06/19/further-evasion-in-the-forgotten-corners-of-ms-xls/
        // Reference: https://github.com/michaelweber/Macrome
        $string20 = /.{0,1000}\-\-payload\-type\sMacro.{0,1000}/ nocase ascii wide
        // Description: An Excel Macro Document Reader/Writer for Red Teamers & Analysts. Blog posts describing what this tool actually does can be found https://malware.pizza/2020/05/12/evading-av-with-excel-macros-and-biff8-xls/ and https://malware.pizza/2020/06/19/further-evasion-in-the-forgotten-corners-of-ms-xls/
        // Reference: https://github.com/michaelweber/Macrome
        $string21 = /.{0,1000}ReadyToPhish\.xls.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
