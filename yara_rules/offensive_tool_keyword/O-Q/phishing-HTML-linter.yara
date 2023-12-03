rule phishing_HTML_linter
{
    meta:
        description = "Detection patterns for the tool 'phishing-HTML-linter' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "phishing-HTML-linter"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Phishing and Social-Engineering related scripts
        // Reference: https://github.com/mgeeky/Penetration-Testing-Tools/blob/master/phishing
        $string1 = /.{0,1000}\/VisualBasicObfuscator.{0,1000}/ nocase ascii wide
        // Description: Phishing and Social-Engineering related scripts
        // Reference: https://github.com/mgeeky/Penetration-Testing-Tools/blob/master/phishing
        $string2 = /.{0,1000}DancingRightToLeft\.py.{0,1000}/ nocase ascii wide
        // Description: Phishing and Social-Engineering related scripts
        // Reference: https://github.com/mgeeky/Penetration-Testing-Tools/blob/master/phishing
        $string3 = /.{0,1000}gophish\-send\-mail\.py.{0,1000}/ nocase ascii wide
        // Description: Phishing and Social-Engineering related scripts
        // Reference: https://github.com/mgeeky/Penetration-Testing-Tools/blob/master/phishing
        $string4 = /.{0,1000}MacroDetectSandbox\.vbs.{0,1000}/ nocase ascii wide
        // Description: Phishing and Social-Engineering related scripts
        // Reference: https://github.com/mgeeky/Penetration-Testing-Tools/blob/master/phishing
        $string5 = /.{0,1000}Phish\-Creds\.ps1.{0,1000}/ nocase ascii wide
        // Description: Phishing and Social-Engineering related scripts
        // Reference: https://github.com/mgeeky/Penetration-Testing-Tools/blob/master/phishing
        $string6 = /.{0,1000}phishing\-HTML\-linter\..{0,1000}/ nocase ascii wide
        // Description: Phishing and Social-Engineering related scripts
        // Reference: https://github.com/mgeeky/Penetration-Testing-Tools/blob/master/phishing
        $string7 = /.{0,1000}RobustPentestMacro.{0,1000}/ nocase ascii wide
        // Description: Phishing and Social-Engineering related scripts
        // Reference: https://github.com/mgeeky/Penetration-Testing-Tools/blob/master/phishing
        $string8 = /.{0,1000}vba\-macro\-mac\-persistence\.vbs.{0,1000}/ nocase ascii wide
        // Description: Phishing and Social-Engineering related scripts
        // Reference: https://github.com/mgeeky/Penetration-Testing-Tools/blob/master/phishing
        $string9 = /.{0,1000}vba\-windows\-persistence\.vbs.{0,1000}/ nocase ascii wide
        // Description: Phishing and Social-Engineering related scripts
        // Reference: https://github.com/mgeeky/Penetration-Testing-Tools/blob/master/phishing
        $string10 = /.{0,1000}WMIPersistence\.vbs.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
