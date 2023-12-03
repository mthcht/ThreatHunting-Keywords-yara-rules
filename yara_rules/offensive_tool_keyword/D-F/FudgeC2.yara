rule FudgeC2
{
    meta:
        description = "Detection patterns for the tool 'FudgeC2' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "FudgeC2"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: FudgeC2 - a command and control framework designed for team collaboration and post-exploitation activities.
        // Reference: https://github.com/Ziconius/FudgeC2
        $string1 = /.{0,1000}\sFudgeC2\s.{0,1000}/ nocase ascii wide
        // Description: FudgeC2 - a command and control framework designed for team collaboration and post-exploitation activities.
        // Reference: https://github.com/Ziconius/FudgeC2
        $string2 = /.{0,1000}\/api\/v1\/campaign\/.{0,1000}\/implants\/.{0,1000}/ nocase ascii wide
        // Description: FudgeC2 - a command and control framework designed for team collaboration and post-exploitation activities.
        // Reference: https://github.com/Ziconius/FudgeC2
        $string3 = /.{0,1000}\/api\/v1\/implants\/.{0,1000}\/execute.{0,1000}/ nocase ascii wide
        // Description: FudgeC2 - a command and control framework designed for team collaboration and post-exploitation activities.
        // Reference: https://github.com/Ziconius/FudgeC2
        $string4 = /.{0,1000}\/api\/v1\/implants\/.{0,1000}\/responses.{0,1000}/ nocase ascii wide
        // Description: FudgeC2 - a command and control framework designed for team collaboration and post-exploitation activities.
        // Reference: https://github.com/Ziconius/FudgeC2
        $string5 = /.{0,1000}\/c2_server\/resources.{0,1000}/ nocase ascii wide
        // Description: FudgeC2 - a command and control framework designed for team collaboration and post-exploitation activities.
        // Reference: https://github.com/Ziconius/FudgeC2
        $string6 = /.{0,1000}\/campaign\/.{0,1000}\/implant\/get_all.{0,1000}/ nocase ascii wide
        // Description: FudgeC2 - a command and control framework designed for team collaboration and post-exploitation activities.
        // Reference: https://github.com/Ziconius/FudgeC2
        $string7 = /.{0,1000}\/FudgeC2.{0,1000}/ nocase ascii wide
        // Description: FudgeC2 - a command and control framework designed for team collaboration and post-exploitation activities.
        // Reference: https://github.com/Ziconius/FudgeC2
        $string8 = /.{0,1000}\/implant\/register_cmd.{0,1000}/ nocase ascii wide
        // Description: FudgeC2 - a command and control framework designed for team collaboration and post-exploitation activities.
        // Reference: https://github.com/Ziconius/FudgeC2
        $string9 = /.{0,1000}\\FudgeC2.{0,1000}/ nocase ascii wide
        // Description: FudgeC2 - a command and control framework designed for team collaboration and post-exploitation activities.
        // Reference: https://github.com/Ziconius/FudgeC2
        $string10 = /.{0,1000}bob\@moozle\.wtf.{0,1000}/ nocase ascii wide
        // Description: FudgeC2 - a command and control framework designed for team collaboration and post-exploitation activities.
        // Reference: https://github.com/Ziconius/FudgeC2
        $string11 = /.{0,1000}c2_server.{0,1000}\.py.{0,1000}/ nocase ascii wide
        // Description: FudgeC2 - a command and control framework designed for team collaboration and post-exploitation activities.
        // Reference: https://github.com/Ziconius/FudgeC2
        $string12 = /.{0,1000}c2_server\.resources.{0,1000}/ nocase ascii wide
        // Description: FudgeC2 - a command and control framework designed for team collaboration and post-exploitation activities.
        // Reference: https://github.com/Ziconius/FudgeC2
        $string13 = /.{0,1000}enable_persistence\.py.{0,1000}/ nocase ascii wide
        // Description: FudgeC2 - a command and control framework designed for team collaboration and post-exploitation activities.
        // Reference: https://github.com/Ziconius/FudgeC2
        $string14 = /.{0,1000}FudgeC2\..{0,1000}/ nocase ascii wide
        // Description: FudgeC2 - a command and control framework designed for team collaboration and post-exploitation activities.
        // Reference: https://github.com/Ziconius/FudgeC2
        $string15 = /.{0,1000}FudgeC2Viewer\.py.{0,1000}/ nocase ascii wide
        // Description: FudgeC2 - a command and control framework designed for team collaboration and post-exploitation activities.
        // Reference: https://github.com/Ziconius/FudgeC2
        $string16 = /.{0,1000}get_list_of_implant_text.{0,1000}/ nocase ascii wide
        // Description: FudgeC2 - a command and control framework designed for team collaboration and post-exploitation activities.
        // Reference: https://github.com/Ziconius/FudgeC2
        $string17 = /.{0,1000}get_obfucation_string_dict.{0,1000}/ nocase ascii wide
        // Description: FudgeC2 - a command and control framework designed for team collaboration and post-exploitation activities.
        // Reference: https://github.com/Ziconius/FudgeC2
        $string18 = /.{0,1000}Implant\.ImplantGenerator.{0,1000}/ nocase ascii wide
        // Description: FudgeC2 - a command and control framework designed for team collaboration and post-exploitation activities.
        // Reference: https://github.com/Ziconius/FudgeC2
        $string19 = /.{0,1000}import\sEnablePersistence.{0,1000}/ nocase ascii wide
        // Description: FudgeC2 - a command and control framework designed for team collaboration and post-exploitation activities.
        // Reference: https://github.com/Ziconius/FudgeC2
        $string20 = /.{0,1000}john\@moozle\.wtf.{0,1000}/ nocase ascii wide
        // Description: FudgeC2 - a command and control framework designed for team collaboration and post-exploitation activities.
        // Reference: https://github.com/Ziconius/FudgeC2
        $string21 = /.{0,1000}payload_encryption\.py.{0,1000}/ nocase ascii wide
        // Description: FudgeC2 - a command and control framework designed for team collaboration and post-exploitation activities.
        // Reference: https://github.com/Ziconius/FudgeC2
        $string22 = /.{0,1000}PSObfucate\.py.{0,1000}/ nocase ascii wide
        // Description: FudgeC2 - a command and control framework designed for team collaboration and post-exploitation activities.
        // Reference: https://github.com/Ziconius/FudgeC2
        $string23 = /.{0,1000}Ziconius\/FudgeC2.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
