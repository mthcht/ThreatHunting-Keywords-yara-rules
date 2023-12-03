rule EmbedInHTML
{
    meta:
        description = "Detection patterns for the tool 'EmbedInHTML' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "EmbedInHTML"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: What this tool does is taking a file (any type of file). encrypt it. and embed it into an HTML file as ressource. along with an automatic download routine simulating a user clicking on the embedded ressource.
        // Reference: https://github.com/Arno0x/EmbedInHTML
        $string1 = /.{0,1000}\.py\s\s\-k\s.{0,1000}\s\-f\s.{0,1000}\.bat\s\-o\s.{0,1000}\.html.{0,1000}/ nocase ascii wide
        // Description: What this tool does is taking a file (any type of file). encrypt it. and embed it into an HTML file as ressource. along with an automatic download routine simulating a user clicking on the embedded ressource.
        // Reference: https://github.com/Arno0x/EmbedInHTML
        $string2 = /.{0,1000}\.py\s\s\-k\s.{0,1000}\s\-f\s.{0,1000}\.docm\s\-o\s.{0,1000}\.html.{0,1000}/ nocase ascii wide
        // Description: What this tool does is taking a file (any type of file). encrypt it. and embed it into an HTML file as ressource. along with an automatic download routine simulating a user clicking on the embedded ressource.
        // Reference: https://github.com/Arno0x/EmbedInHTML
        $string3 = /.{0,1000}\.py\s\s\-k\s.{0,1000}\s\-f\s.{0,1000}\.docx\s\-o\s.{0,1000}\.html.{0,1000}/ nocase ascii wide
        // Description: What this tool does is taking a file (any type of file). encrypt it. and embed it into an HTML file as ressource. along with an automatic download routine simulating a user clicking on the embedded ressource.
        // Reference: https://github.com/Arno0x/EmbedInHTML
        $string4 = /.{0,1000}\.py\s\s\-k\s.{0,1000}\s\-f\s.{0,1000}\.exe\s\-o\s.{0,1000}\.html.{0,1000}/ nocase ascii wide
        // Description: What this tool does is taking a file (any type of file). encrypt it. and embed it into an HTML file as ressource. along with an automatic download routine simulating a user clicking on the embedded ressource.
        // Reference: https://github.com/Arno0x/EmbedInHTML
        $string5 = /.{0,1000}\.py\s\s\-k\s.{0,1000}\s\-f\s.{0,1000}\.js\s\-o\s.{0,1000}\.html.{0,1000}/ nocase ascii wide
        // Description: What this tool does is taking a file (any type of file). encrypt it. and embed it into an HTML file as ressource. along with an automatic download routine simulating a user clicking on the embedded ressource.
        // Reference: https://github.com/Arno0x/EmbedInHTML
        $string6 = /.{0,1000}\.py\s\s\-k\s.{0,1000}\s\-f\s.{0,1000}\.pps\s\-o\s.{0,1000}\.html.{0,1000}/ nocase ascii wide
        // Description: What this tool does is taking a file (any type of file). encrypt it. and embed it into an HTML file as ressource. along with an automatic download routine simulating a user clicking on the embedded ressource.
        // Reference: https://github.com/Arno0x/EmbedInHTML
        $string7 = /.{0,1000}\.py\s\s\-k\s.{0,1000}\s\-f\s.{0,1000}\.ppsx\s\-o\s.{0,1000}\.html.{0,1000}/ nocase ascii wide
        // Description: What this tool does is taking a file (any type of file). encrypt it. and embed it into an HTML file as ressource. along with an automatic download routine simulating a user clicking on the embedded ressource.
        // Reference: https://github.com/Arno0x/EmbedInHTML
        $string8 = /.{0,1000}\.py\s\s\-k\s.{0,1000}\s\-f\s.{0,1000}\.ppt\s\-o\s.{0,1000}\.html.{0,1000}/ nocase ascii wide
        // Description: What this tool does is taking a file (any type of file). encrypt it. and embed it into an HTML file as ressource. along with an automatic download routine simulating a user clicking on the embedded ressource.
        // Reference: https://github.com/Arno0x/EmbedInHTML
        $string9 = /.{0,1000}\.py\s\s\-k\s.{0,1000}\s\-f\s.{0,1000}\.ps1\s\-o\s.{0,1000}\.html.{0,1000}/ nocase ascii wide
        // Description: What this tool does is taking a file (any type of file). encrypt it. and embed it into an HTML file as ressource. along with an automatic download routine simulating a user clicking on the embedded ressource.
        // Reference: https://github.com/Arno0x/EmbedInHTML
        $string10 = /.{0,1000}\.py\s\s\-k\s.{0,1000}\s\-f\s.{0,1000}\.xll\s\-o\s.{0,1000}\.html.{0,1000}/ nocase ascii wide
        // Description: What this tool does is taking a file (any type of file). encrypt it. and embed it into an HTML file as ressource. along with an automatic download routine simulating a user clicking on the embedded ressource.
        // Reference: https://github.com/Arno0x/EmbedInHTML
        $string11 = /.{0,1000}\.py\s\s\-k\s.{0,1000}\s\-f\s.{0,1000}\.xls\s\-o\s.{0,1000}\.html.{0,1000}/ nocase ascii wide
        // Description: What this tool does is taking a file (any type of file). encrypt it. and embed it into an HTML file as ressource. along with an automatic download routine simulating a user clicking on the embedded ressource.
        // Reference: https://github.com/Arno0x/EmbedInHTML
        $string12 = /.{0,1000}\.py\s\s\-k\s.{0,1000}\s\-f\s.{0,1000}\.xlsb\s\-o\s.{0,1000}\.html.{0,1000}/ nocase ascii wide
        // Description: What this tool does is taking a file (any type of file). encrypt it. and embed it into an HTML file as ressource. along with an automatic download routine simulating a user clicking on the embedded ressource.
        // Reference: https://github.com/Arno0x/EmbedInHTML
        $string13 = /.{0,1000}\.py\s\s\-k\s.{0,1000}\s\-f\s.{0,1000}\.xlsm\s\-o\s.{0,1000}\.html.{0,1000}/ nocase ascii wide
        // Description: What this tool does is taking a file (any type of file). encrypt it. and embed it into an HTML file as ressource. along with an automatic download routine simulating a user clicking on the embedded ressource.
        // Reference: https://github.com/Arno0x/EmbedInHTML
        $string14 = /.{0,1000}\.py\s\s\-k\s.{0,1000}\s\-f\s.{0,1000}\.xlsx\s\-o\s.{0,1000}\.html.{0,1000}/ nocase ascii wide
        // Description: What this tool does is taking a file (any type of file). encrypt it. and embed it into an HTML file as ressource. along with an automatic download routine simulating a user clicking on the embedded ressource.
        // Reference: https://github.com/Arno0x/EmbedInHTML
        $string15 = /.{0,1000}\.py\s\-k\s.{0,1000}\s\-f\s.{0,1000}\.doc\s\-o\s.{0,1000}\.html.{0,1000}/ nocase ascii wide
        // Description: What this tool does is taking a file (any type of file). encrypt it. and embed it into an HTML file as ressource. along with an automatic download routine simulating a user clicking on the embedded ressource.
        // Reference: https://github.com/Arno0x/EmbedInHTML
        $string16 = /.{0,1000}\/agent\/stagers\/dropbox\.py.{0,1000}/ nocase ascii wide
        // Description: What this tool does is taking a file (any type of file). encrypt it. and embed it into an HTML file as ressource. along with an automatic download routine simulating a user clicking on the embedded ressource.
        // Reference: https://github.com/Arno0x/EmbedInHTML
        $string17 = /.{0,1000}\/EmbedInHTML\.git.{0,1000}/ nocase ascii wide
        // Description: What this tool does is taking a file (any type of file). encrypt it. and embed it into an HTML file as ressource. along with an automatic download routine simulating a user clicking on the embedded ressource.
        // Reference: https://github.com/Arno0x/EmbedInHTML
        $string18 = /.{0,1000}\/EmbedInHTML\/.{0,1000}/ nocase ascii wide
        // Description: What this tool does is taking a file (any type of file). encrypt it. and embed it into an HTML file as ressource. along with an automatic download routine simulating a user clicking on the embedded ressource.
        // Reference: https://github.com/Arno0x/EmbedInHTML
        $string19 = /.{0,1000}Arno0x\/EmbedInHTML.{0,1000}/ nocase ascii wide
        // Description: What this tool does is taking a file (any type of file). encrypt it. and embed it into an HTML file as ressource. along with an automatic download routine simulating a user clicking on the embedded ressource.
        // Reference: https://github.com/Arno0x/EmbedInHTML
        $string20 = /.{0,1000}embedInHTML\.html.{0,1000}/ nocase ascii wide
        // Description: What this tool does is taking a file (any type of file). encrypt it. and embed it into an HTML file as ressource. along with an automatic download routine simulating a user clicking on the embedded ressource.
        // Reference: https://github.com/Arno0x/EmbedInHTML
        $string21 = /.{0,1000}embedInHTML\.py.{0,1000}/ nocase ascii wide
        // Description: What this tool does is taking a file (any type of file). encrypt it. and embed it into an HTML file as ressource. along with an automatic download routine simulating a user clicking on the embedded ressource.
        // Reference: https://github.com/Arno0x/EmbedInHTML
        $string22 = /.{0,1000}EmbedInHTML\-master.{0,1000}/ nocase ascii wide
        // Description: What this tool does is taking a file (any type of file). encrypt it. and embed it into an HTML file as ressource. along with an automatic download routine simulating a user clicking on the embedded ressource.
        // Reference: https://github.com/Arno0x/EmbedInHTML
        $string23 = /.{0,1000}\-f\spayloads_examples\/calc\..{0,1000}/ nocase ascii wide
        // Description: What this tool does is taking a file (any type of file). encrypt it. and embed it into an HTML file as ressource. along with an automatic download routine simulating a user clicking on the embedded ressource.
        // Reference: https://github.com/Arno0x/EmbedInHTML
        $string24 = /.{0,1000}payloads_examples.{0,1000}calc\.js.{0,1000}/ nocase ascii wide
        // Description: What this tool does is taking a file (any type of file). encrypt it. and embed it into an HTML file as ressource. along with an automatic download routine simulating a user clicking on the embedded ressource.
        // Reference: https://github.com/Arno0x/EmbedInHTML
        $string25 = /.{0,1000}payloads_examples.{0,1000}calc\.xll.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
