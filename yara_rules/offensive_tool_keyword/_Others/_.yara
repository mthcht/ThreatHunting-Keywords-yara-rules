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
        $string1 = /\.doc\.bat/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string2 = /\.doc\.dll/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string3 = /\.doc\.exe/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string4 = /\.doc\.htm/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string5 = /\.doc\.jar/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string6 = /\.doc\.js/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string7 = /\.doc\.sfx/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string8 = /\.doc\.vbs/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string9 = /\.docx\.bat/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string10 = /\.docx\.dll/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string11 = /\.docx\.exe/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string12 = /\.docx\.htm/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string13 = /\.docx\.jar/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string14 = /\.docx\.js/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string15 = /\.docx\.sfx/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string16 = /\.docx\.vbs/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string17 = /\.pdf\.bat/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string18 = /\.pdf\.dll/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string19 = /\.pdf\.exe/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string20 = /\.pdf\.htm/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string21 = /\.pdf\.jar/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string22 = /\.pdf\.js/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string23 = /\.pdf\.sfx/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string24 = /\.pdf\.vbs/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string25 = /\.ppt\.bat/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string26 = /\.ppt\.dll/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string27 = /\.ppt\.exe/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string28 = /\.ppt\.htm/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string29 = /\.ppt\.jar/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string30 = /\.ppt\.js/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string31 = /\.ppt\.sfx/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string32 = /\.ppt\.vbs/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string33 = /\.pptx\.bat/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string34 = /\.pptx\.dll/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string35 = /\.pptx\.exe/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string36 = /\.pptx\.htm/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string37 = /\.pptx\.jar/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string38 = /\.pptx\.js/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string39 = /\.pptx\.sfx/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string40 = /\.pptx\.vbs/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string41 = /\.rtf\.bat/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string42 = /\.rtf\.dll/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string43 = /\.rtf\.exe/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string44 = /\.rtf\.htm/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string45 = /\.rtf\.jar/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string46 = /\.rtf\.js/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string47 = /\.rtf\.sfx/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string48 = /\.rtf\.vbs/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string49 = /\.txt\.bat/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string50 = /\.txt\.dll/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string51 = /\.txt\.exe/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string52 = /\.txt\.htm/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string53 = /\.txt\.jar/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string54 = /\.txt\.js/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string55 = /\.txt\.sfx/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string56 = /\.txt\.vbs/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string57 = /\.xls\.bat/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string58 = /\.xls\.dll/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string59 = /\.xls\.exe/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string60 = /\.xls\.htm/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string61 = /\.xls\.jar/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string62 = /\.xls\.js/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string63 = /\.xls\.sfx/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string64 = /\.xls\.vbs/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string65 = /\.xlsx\.bat/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string66 = /\.xlsx\.dll/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string67 = /\.xlsx\.exe/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string68 = /\.xlsx\.htm/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string69 = /\.xlsx\.jar/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string70 = /\.xlsx\.js/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string71 = /\.xlsx\.sfx/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string72 = /\.xlsx\.vbs/ nocase ascii wide
        // Description: keyword observed in multiple backdoor tools
        // Reference: N/A
        $string73 = /\/BackDoor/ nocase ascii wide
        // Description: pentest keyword detection. detect potential pentesters using this keyword in file name. repository or command line
        // Reference: N/A
        $string74 = /\/pentest/ nocase ascii wide
        // Description: pentest keyword detection. detect potential pentesters using this keyword in file name. repository or command line
        // Reference: N/A
        $string75 = /\-pentest/ nocase ascii wide
        // Description: windows exploit keyword often used in poc exploit github repo or could be a file name or folder
        // Reference: N/A
        $string76 = /Windows\sExploit/ nocase ascii wide

    condition:
        any of them
}