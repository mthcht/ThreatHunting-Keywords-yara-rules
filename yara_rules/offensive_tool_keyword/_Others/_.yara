rule _
{
    meta:
        description = "Detection patterns for the tool '_' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "_"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Suspicious extensions files
        // Reference: N/A
        $string1 = /.{0,1000}\.doc\.bat.{0,1000}/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string2 = /.{0,1000}\.doc\.dll.{0,1000}/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string3 = /.{0,1000}\.doc\.exe.{0,1000}/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string4 = /.{0,1000}\.doc\.htm.{0,1000}/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string5 = /.{0,1000}\.doc\.jar.{0,1000}/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string6 = /.{0,1000}\.doc\.js.{0,1000}/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string7 = /.{0,1000}\.doc\.sfx.{0,1000}/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string8 = /.{0,1000}\.doc\.vbs.{0,1000}/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string9 = /.{0,1000}\.docx\.bat.{0,1000}/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string10 = /.{0,1000}\.docx\.dll.{0,1000}/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string11 = /.{0,1000}\.docx\.exe.{0,1000}/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string12 = /.{0,1000}\.docx\.htm.{0,1000}/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string13 = /.{0,1000}\.docx\.jar.{0,1000}/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string14 = /.{0,1000}\.docx\.js.{0,1000}/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string15 = /.{0,1000}\.docx\.sfx.{0,1000}/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string16 = /.{0,1000}\.docx\.vbs.{0,1000}/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string17 = /.{0,1000}\.pdf\.bat.{0,1000}/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string18 = /.{0,1000}\.pdf\.dll.{0,1000}/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string19 = /.{0,1000}\.pdf\.exe.{0,1000}/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string20 = /.{0,1000}\.pdf\.htm.{0,1000}/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string21 = /.{0,1000}\.pdf\.jar.{0,1000}/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string22 = /.{0,1000}\.pdf\.js.{0,1000}/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string23 = /.{0,1000}\.pdf\.sfx.{0,1000}/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string24 = /.{0,1000}\.pdf\.vbs.{0,1000}/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string25 = /.{0,1000}\.ppt\.bat.{0,1000}/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string26 = /.{0,1000}\.ppt\.dll.{0,1000}/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string27 = /.{0,1000}\.ppt\.exe.{0,1000}/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string28 = /.{0,1000}\.ppt\.htm.{0,1000}/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string29 = /.{0,1000}\.ppt\.jar.{0,1000}/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string30 = /.{0,1000}\.ppt\.js.{0,1000}/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string31 = /.{0,1000}\.ppt\.sfx.{0,1000}/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string32 = /.{0,1000}\.ppt\.vbs.{0,1000}/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string33 = /.{0,1000}\.pptx\.bat.{0,1000}/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string34 = /.{0,1000}\.pptx\.dll.{0,1000}/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string35 = /.{0,1000}\.pptx\.exe.{0,1000}/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string36 = /.{0,1000}\.pptx\.htm.{0,1000}/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string37 = /.{0,1000}\.pptx\.jar.{0,1000}/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string38 = /.{0,1000}\.pptx\.js.{0,1000}/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string39 = /.{0,1000}\.pptx\.sfx.{0,1000}/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string40 = /.{0,1000}\.pptx\.vbs.{0,1000}/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string41 = /.{0,1000}\.rtf\.bat.{0,1000}/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string42 = /.{0,1000}\.rtf\.dll.{0,1000}/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string43 = /.{0,1000}\.rtf\.exe.{0,1000}/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string44 = /.{0,1000}\.rtf\.htm.{0,1000}/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string45 = /.{0,1000}\.rtf\.jar.{0,1000}/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string46 = /.{0,1000}\.rtf\.js.{0,1000}/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string47 = /.{0,1000}\.rtf\.sfx.{0,1000}/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string48 = /.{0,1000}\.rtf\.vbs.{0,1000}/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string49 = /.{0,1000}\.txt\.bat.{0,1000}/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string50 = /.{0,1000}\.txt\.dll.{0,1000}/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string51 = /.{0,1000}\.txt\.exe.{0,1000}/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string52 = /.{0,1000}\.txt\.htm.{0,1000}/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string53 = /.{0,1000}\.txt\.jar.{0,1000}/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string54 = /.{0,1000}\.txt\.js.{0,1000}/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string55 = /.{0,1000}\.txt\.sfx.{0,1000}/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string56 = /.{0,1000}\.txt\.vbs.{0,1000}/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string57 = /.{0,1000}\.xls\.bat.{0,1000}/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string58 = /.{0,1000}\.xls\.dll.{0,1000}/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string59 = /.{0,1000}\.xls\.exe.{0,1000}/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string60 = /.{0,1000}\.xls\.htm.{0,1000}/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string61 = /.{0,1000}\.xls\.jar.{0,1000}/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string62 = /.{0,1000}\.xls\.js.{0,1000}/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string63 = /.{0,1000}\.xls\.sfx.{0,1000}/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string64 = /.{0,1000}\.xls\.vbs.{0,1000}/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string65 = /.{0,1000}\.xlsx\.bat.{0,1000}/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string66 = /.{0,1000}\.xlsx\.dll.{0,1000}/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string67 = /.{0,1000}\.xlsx\.exe.{0,1000}/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string68 = /.{0,1000}\.xlsx\.htm.{0,1000}/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string69 = /.{0,1000}\.xlsx\.jar.{0,1000}/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string70 = /.{0,1000}\.xlsx\.js.{0,1000}/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string71 = /.{0,1000}\.xlsx\.sfx.{0,1000}/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string72 = /.{0,1000}\.xlsx\.vbs.{0,1000}/ nocase ascii wide
        // Description: keyword observed in multiple backdoor tools
        // Reference: N/A
        $string73 = /.{0,1000}\/BackDoor.{0,1000}/ nocase ascii wide
        // Description: pentest keyword detection. detect potential pentesters using this keyword in file name. repository or command line
        // Reference: N/A
        $string74 = /.{0,1000}\/pentest.{0,1000}/ nocase ascii wide
        // Description: pentest keyword detection. detect potential pentesters using this keyword in file name. repository or command line
        // Reference: N/A
        $string75 = /.{0,1000}\-pentest.{0,1000}/ nocase ascii wide
        // Description: windows exploit keyword often used in poc exploit github repo or could be a file name or folder
        // Reference: N/A
        $string76 = /.{0,1000}Windows\sExploit.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
