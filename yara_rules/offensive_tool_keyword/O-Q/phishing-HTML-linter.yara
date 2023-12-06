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
        $string1 = /\/VisualBasicObfuscator/ nocase ascii wide
        // Description: Phishing and Social-Engineering related scripts
        // Reference: https://github.com/mgeeky/Penetration-Testing-Tools/blob/master/phishing
        $string2 = /DancingRightToLeft\.py/ nocase ascii wide
        // Description: Phishing and Social-Engineering related scripts
        // Reference: https://github.com/mgeeky/Penetration-Testing-Tools/blob/master/phishing
        $string3 = /gophish\-send\-mail\.py/ nocase ascii wide
        // Description: Phishing and Social-Engineering related scripts
        // Reference: https://github.com/mgeeky/Penetration-Testing-Tools/blob/master/phishing
        $string4 = /MacroDetectSandbox\.vbs/ nocase ascii wide
        // Description: Phishing and Social-Engineering related scripts
        // Reference: https://github.com/mgeeky/Penetration-Testing-Tools/blob/master/phishing
        $string5 = /Phish\-Creds\.ps1/ nocase ascii wide
        // Description: Phishing and Social-Engineering related scripts
        // Reference: https://github.com/mgeeky/Penetration-Testing-Tools/blob/master/phishing
        $string6 = /phishing\-HTML\-linter\./ nocase ascii wide
        // Description: Phishing and Social-Engineering related scripts
        // Reference: https://github.com/mgeeky/Penetration-Testing-Tools/blob/master/phishing
        $string7 = /RobustPentestMacro/ nocase ascii wide
        // Description: Phishing and Social-Engineering related scripts
        // Reference: https://github.com/mgeeky/Penetration-Testing-Tools/blob/master/phishing
        $string8 = /vba\-macro\-mac\-persistence\.vbs/ nocase ascii wide
        // Description: Phishing and Social-Engineering related scripts
        // Reference: https://github.com/mgeeky/Penetration-Testing-Tools/blob/master/phishing
        $string9 = /vba\-windows\-persistence\.vbs/ nocase ascii wide
        // Description: Phishing and Social-Engineering related scripts
        // Reference: https://github.com/mgeeky/Penetration-Testing-Tools/blob/master/phishing
        $string10 = /WMIPersistence\.vbs/ nocase ascii wide

    condition:
        any of them
}
