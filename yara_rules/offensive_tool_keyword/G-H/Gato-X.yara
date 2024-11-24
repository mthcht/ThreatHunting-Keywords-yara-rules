rule Gato_X
{
    meta:
        description = "Detection patterns for the tool 'Gato-X' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Gato-X"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: automate advanced enumeration and exploitation techniques against GitHub repositories and organizations
        // Reference: https://github.com/adnanekhan/Gato-X
        $string1 = /\/gato_x\-0\.5\.2\.tar\.gz/ nocase ascii wide
        // Description: automate advanced enumeration and exploitation techniques against GitHub repositories and organizations
        // Reference: https://github.com/adnanekhan/Gato-X
        $string2 = /\/gato_x\-0\.5\.3\.tar\.gz/ nocase ascii wide
        // Description: automate advanced enumeration and exploitation techniques against GitHub repositories and organizations
        // Reference: https://github.com/adnanekhan/Gato-X
        $string3 = /\/Gato\-X\.git/ nocase ascii wide
        // Description: automate advanced enumeration and exploitation techniques against GitHub repositories and organizations
        // Reference: https://github.com/adnanekhan/Gato-X
        $string4 = "018a8c1acc14adf544c2d05b066556e7b67e3756e30e928a4ff79cde74229086" nocase ascii wide
        // Description: automate advanced enumeration and exploitation techniques against GitHub repositories and organizations
        // Reference: https://github.com/adnanekhan/Gato-X
        $string5 = "061425625f0c923443e3329439f21d03796f26b41c1b0e3628a2ea564ff733e8" nocase ascii wide
        // Description: automate advanced enumeration and exploitation techniques against GitHub repositories and organizations
        // Reference: https://github.com/adnanekhan/Gato-X
        $string6 = "2de627c776ab1a97d9ea2b3b16f63ef060cf4e0367f03861c85fec6106b2a7af" nocase ascii wide
        // Description: automate advanced enumeration and exploitation techniques against GitHub repositories and organizations
        // Reference: https://github.com/adnanekhan/Gato-X
        $string7 = "58993d929685b240f375125ce5ad0540f57f6eed29b6feebaff194c061119052" nocase ascii wide
        // Description: automate advanced enumeration and exploitation techniques against GitHub repositories and organizations
        // Reference: https://github.com/adnanekhan/Gato-X
        $string8 = "5905bf979bb3d714c2641502161d807723fc79cfc9b58cbe2a95882f12623778" nocase ascii wide
        // Description: automate advanced enumeration and exploitation techniques against GitHub repositories and organizations
        // Reference: https://github.com/adnanekhan/Gato-X
        $string9 = "76e94a8b2541bd3c626fa5ac014d78665088f69c3b95925ea4211e68827fa1c0" nocase ascii wide
        // Description: automate advanced enumeration and exploitation techniques against GitHub repositories and organizations
        // Reference: https://github.com/adnanekhan/Gato-X
        $string10 = "a3cb4dc05b5c42059a88e8bce99878c5228bb139b7bd3e2b36588d9ce4968141" nocase ascii wide
        // Description: automate advanced enumeration and exploitation techniques against GitHub repositories and organizations
        // Reference: https://github.com/adnanekhan/Gato-X
        $string11 = "a5789291ca04f1490a7b9478a9b8e1c37b594a59a101fd63d17a3eea11d04cd8" nocase ascii wide
        // Description: automate advanced enumeration and exploitation techniques against GitHub repositories and organizations
        // Reference: https://github.com/adnanekhan/Gato-X
        $string12 = "adnanekhan/Gato-X" nocase ascii wide
        // Description: automate advanced enumeration and exploitation techniques against GitHub repositories and organizations
        // Reference: https://github.com/adnanekhan/Gato-X
        $string13 = "b7a5527f8a5f361fc787facc955937ea2294a883a63e5ad4abf1c9ed26b49ccd" nocase ascii wide
        // Description: automate advanced enumeration and exploitation techniques against GitHub repositories and organizations
        // Reference: https://github.com/adnanekhan/Gato-X
        $string14 = "bb2dae47e442008e774626bfaa7fdeaec3eb2bacdf307d547b3205e2ecad3513" nocase ascii wide
        // Description: automate advanced enumeration and exploitation techniques against GitHub repositories and organizations
        // Reference: https://github.com/adnanekhan/Gato-X
        $string15 = "be7732144c35e08d90a04d6d668c29b4341a44428b3d9c08ae69865bd3b97f17" nocase ascii wide
        // Description: automate advanced enumeration and exploitation techniques against GitHub repositories and organizations
        // Reference: https://github.com/adnanekhan/Gato-X
        $string16 = "f71501c6dbf8e31c30fabed0786fa3145af0e8862712f5803c0c4177fb8d1836" nocase ascii wide
        // Description: automate advanced enumeration and exploitation techniques against GitHub repositories and organizations
        // Reference: https://github.com/adnanekhan/Gato-X
        $string17 = /from\sgatox\.attack\.attack\simport\s/ nocase ascii wide
        // Description: automate advanced enumeration and exploitation techniques against GitHub repositories and organizations
        // Reference: https://github.com/adnanekhan/Gato-X
        $string18 = /from\sgatox\.attack\.cicd_attack\simport\s/ nocase ascii wide
        // Description: automate advanced enumeration and exploitation techniques against GitHub repositories and organizations
        // Reference: https://github.com/adnanekhan/Gato-X
        $string19 = /from\sgatox\.cli\simport\scli/ nocase ascii wide
        // Description: automate advanced enumeration and exploitation techniques against GitHub repositories and organizations
        // Reference: https://github.com/adnanekhan/Gato-X
        $string20 = /from\sgatox\.cli\.output\simport\s/ nocase ascii wide
        // Description: automate advanced enumeration and exploitation techniques against GitHub repositories and organizations
        // Reference: https://github.com/adnanekhan/Gato-X
        $string21 = /from\sgatox\.github\.api\simport\s/ nocase ascii wide
        // Description: automate advanced enumeration and exploitation techniques against GitHub repositories and organizations
        // Reference: https://github.com/adnanekhan/Gato-X
        $string22 = /gato_x\-0\.5\.3\-py3\-none\-any\.whl/ nocase ascii wide
        // Description: automate advanced enumeration and exploitation techniques against GitHub repositories and organizations
        // Reference: https://github.com/adnanekhan/Gato-X
        $string23 = "gato-x attack " nocase ascii wide
        // Description: automate advanced enumeration and exploitation techniques against GitHub repositories and organizations
        // Reference: https://github.com/adnanekhan/Gato-X
        $string24 = "gato-x enum " nocase ascii wide
        // Description: automate advanced enumeration and exploitation techniques against GitHub repositories and organizations
        // Reference: https://github.com/adnanekhan/Gato-X
        $string25 = "gato-x search " nocase ascii wide
        // Description: automate advanced enumeration and exploitation techniques against GitHub repositories and organizations
        // Reference: https://github.com/adnanekhan/Gato-X
        $string26 = /gatox\.cli\.search/ nocase ascii wide
        // Description: automate advanced enumeration and exploitation techniques against GitHub repositories and organizations
        // Reference: https://github.com/adnanekhan/Gato-X
        $string27 = /gatox\.enumerate\.reports\.report/ nocase ascii wide
        // Description: automate advanced enumeration and exploitation techniques against GitHub repositories and organizations
        // Reference: https://github.com/adnanekhan/Gato-X
        $string28 = /gatox\.git\.utils\.subprocess\.run/ nocase ascii wide
        // Description: automate advanced enumeration and exploitation techniques against GitHub repositories and organizations
        // Reference: https://github.com/adnanekhan/Gato-X
        $string29 = /gatox\.github\.api\.open/ nocase ascii wide
        // Description: automate advanced enumeration and exploitation techniques against GitHub repositories and organizations
        // Reference: https://github.com/adnanekhan/Gato-X
        $string30 = /gatox\.github\.api\.requests\.post/ nocase ascii wide
        // Description: automate advanced enumeration and exploitation techniques against GitHub repositories and organizations
        // Reference: https://github.com/adnanekhan/Gato-X
        $string31 = /gatox\.github\.search/ nocase ascii wide
        // Description: automate advanced enumeration and exploitation techniques against GitHub repositories and organizations
        // Reference: https://github.com/adnanekhan/Gato-X
        $string32 = /https\:\/\/api\.github\.com\/orgs\/gatoxtest\// nocase ascii wide
        // Description: automate advanced enumeration and exploitation techniques against GitHub repositories and organizations
        // Reference: https://github.com/adnanekhan/Gato-X
        $string33 = "pip install gato-x" nocase ascii wide

    condition:
        any of them
}
