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
        $string1 = /\.py\s\s\-k\s.{0,1000}\s\-f\s.{0,1000}\.bat\s\-o\s.{0,1000}\.html/ nocase ascii wide
        // Description: What this tool does is taking a file (any type of file). encrypt it. and embed it into an HTML file as ressource. along with an automatic download routine simulating a user clicking on the embedded ressource.
        // Reference: https://github.com/Arno0x/EmbedInHTML
        $string2 = /\.py\s\s\-k\s.{0,1000}\s\-f\s.{0,1000}\.docm\s\-o\s.{0,1000}\.html/ nocase ascii wide
        // Description: What this tool does is taking a file (any type of file). encrypt it. and embed it into an HTML file as ressource. along with an automatic download routine simulating a user clicking on the embedded ressource.
        // Reference: https://github.com/Arno0x/EmbedInHTML
        $string3 = /\.py\s\s\-k\s.{0,1000}\s\-f\s.{0,1000}\.docx\s\-o\s.{0,1000}\.html/ nocase ascii wide
        // Description: What this tool does is taking a file (any type of file). encrypt it. and embed it into an HTML file as ressource. along with an automatic download routine simulating a user clicking on the embedded ressource.
        // Reference: https://github.com/Arno0x/EmbedInHTML
        $string4 = /\.py\s\s\-k\s.{0,1000}\s\-f\s.{0,1000}\.exe\s\-o\s.{0,1000}\.html/ nocase ascii wide
        // Description: What this tool does is taking a file (any type of file). encrypt it. and embed it into an HTML file as ressource. along with an automatic download routine simulating a user clicking on the embedded ressource.
        // Reference: https://github.com/Arno0x/EmbedInHTML
        $string5 = /\.py\s\s\-k\s.{0,1000}\s\-f\s.{0,1000}\.js\s\-o\s.{0,1000}\.html/ nocase ascii wide
        // Description: What this tool does is taking a file (any type of file). encrypt it. and embed it into an HTML file as ressource. along with an automatic download routine simulating a user clicking on the embedded ressource.
        // Reference: https://github.com/Arno0x/EmbedInHTML
        $string6 = /\.py\s\s\-k\s.{0,1000}\s\-f\s.{0,1000}\.pps\s\-o\s.{0,1000}\.html/ nocase ascii wide
        // Description: What this tool does is taking a file (any type of file). encrypt it. and embed it into an HTML file as ressource. along with an automatic download routine simulating a user clicking on the embedded ressource.
        // Reference: https://github.com/Arno0x/EmbedInHTML
        $string7 = /\.py\s\s\-k\s.{0,1000}\s\-f\s.{0,1000}\.ppsx\s\-o\s.{0,1000}\.html/ nocase ascii wide
        // Description: What this tool does is taking a file (any type of file). encrypt it. and embed it into an HTML file as ressource. along with an automatic download routine simulating a user clicking on the embedded ressource.
        // Reference: https://github.com/Arno0x/EmbedInHTML
        $string8 = /\.py\s\s\-k\s.{0,1000}\s\-f\s.{0,1000}\.ppt\s\-o\s.{0,1000}\.html/ nocase ascii wide
        // Description: What this tool does is taking a file (any type of file). encrypt it. and embed it into an HTML file as ressource. along with an automatic download routine simulating a user clicking on the embedded ressource.
        // Reference: https://github.com/Arno0x/EmbedInHTML
        $string9 = /\.py\s\s\-k\s.{0,1000}\s\-f\s.{0,1000}\.ps1\s\-o\s.{0,1000}\.html/ nocase ascii wide
        // Description: What this tool does is taking a file (any type of file). encrypt it. and embed it into an HTML file as ressource. along with an automatic download routine simulating a user clicking on the embedded ressource.
        // Reference: https://github.com/Arno0x/EmbedInHTML
        $string10 = /\.py\s\s\-k\s.{0,1000}\s\-f\s.{0,1000}\.xll\s\-o\s.{0,1000}\.html/ nocase ascii wide
        // Description: What this tool does is taking a file (any type of file). encrypt it. and embed it into an HTML file as ressource. along with an automatic download routine simulating a user clicking on the embedded ressource.
        // Reference: https://github.com/Arno0x/EmbedInHTML
        $string11 = /\.py\s\s\-k\s.{0,1000}\s\-f\s.{0,1000}\.xls\s\-o\s.{0,1000}\.html/ nocase ascii wide
        // Description: What this tool does is taking a file (any type of file). encrypt it. and embed it into an HTML file as ressource. along with an automatic download routine simulating a user clicking on the embedded ressource.
        // Reference: https://github.com/Arno0x/EmbedInHTML
        $string12 = /\.py\s\s\-k\s.{0,1000}\s\-f\s.{0,1000}\.xlsb\s\-o\s.{0,1000}\.html/ nocase ascii wide
        // Description: What this tool does is taking a file (any type of file). encrypt it. and embed it into an HTML file as ressource. along with an automatic download routine simulating a user clicking on the embedded ressource.
        // Reference: https://github.com/Arno0x/EmbedInHTML
        $string13 = /\.py\s\s\-k\s.{0,1000}\s\-f\s.{0,1000}\.xlsm\s\-o\s.{0,1000}\.html/ nocase ascii wide
        // Description: What this tool does is taking a file (any type of file). encrypt it. and embed it into an HTML file as ressource. along with an automatic download routine simulating a user clicking on the embedded ressource.
        // Reference: https://github.com/Arno0x/EmbedInHTML
        $string14 = /\.py\s\s\-k\s.{0,1000}\s\-f\s.{0,1000}\.xlsx\s\-o\s.{0,1000}\.html/ nocase ascii wide
        // Description: What this tool does is taking a file (any type of file). encrypt it. and embed it into an HTML file as ressource. along with an automatic download routine simulating a user clicking on the embedded ressource.
        // Reference: https://github.com/Arno0x/EmbedInHTML
        $string15 = /\.py\s\-k\s.{0,1000}\s\-f\s.{0,1000}\.doc\s\-o\s.{0,1000}\.html/ nocase ascii wide
        // Description: What this tool does is taking a file (any type of file). encrypt it. and embed it into an HTML file as ressource. along with an automatic download routine simulating a user clicking on the embedded ressource.
        // Reference: https://github.com/Arno0x/EmbedInHTML
        $string16 = /\/agent\/stagers\/dropbox\.py/ nocase ascii wide
        // Description: What this tool does is taking a file (any type of file). encrypt it. and embed it into an HTML file as ressource. along with an automatic download routine simulating a user clicking on the embedded ressource.
        // Reference: https://github.com/Arno0x/EmbedInHTML
        $string17 = /\/EmbedInHTML\.git/ nocase ascii wide
        // Description: What this tool does is taking a file (any type of file). encrypt it. and embed it into an HTML file as ressource. along with an automatic download routine simulating a user clicking on the embedded ressource.
        // Reference: https://github.com/Arno0x/EmbedInHTML
        $string18 = "/EmbedInHTML/" nocase ascii wide
        // Description: What this tool does is taking a file (any type of file). encrypt it. and embed it into an HTML file as ressource. along with an automatic download routine simulating a user clicking on the embedded ressource.
        // Reference: https://github.com/Arno0x/EmbedInHTML
        $string19 = "36ff05fc406bf6a2e677374028ba00cb622b2219e44c198d5dd6efae4ae963c3" nocase ascii wide
        // Description: What this tool does is taking a file (any type of file). encrypt it. and embed it into an HTML file as ressource. along with an automatic download routine simulating a user clicking on the embedded ressource.
        // Reference: https://github.com/Arno0x/EmbedInHTML
        $string20 = "809f540f580fc0e192a1c0432ec04105a3faf51f9d7c20f5e15423b78774052d" nocase ascii wide
        // Description: What this tool does is taking a file (any type of file). encrypt it. and embed it into an HTML file as ressource. along with an automatic download routine simulating a user clicking on the embedded ressource.
        // Reference: https://github.com/Arno0x/EmbedInHTML
        $string21 = "Arno0x/EmbedInHTML" nocase ascii wide
        // Description: What this tool does is taking a file (any type of file). encrypt it. and embed it into an HTML file as ressource. along with an automatic download routine simulating a user clicking on the embedded ressource.
        // Reference: https://github.com/Arno0x/EmbedInHTML
        $string22 = /embedInHTML\.html/ nocase ascii wide
        // Description: What this tool does is taking a file (any type of file). encrypt it. and embed it into an HTML file as ressource. along with an automatic download routine simulating a user clicking on the embedded ressource.
        // Reference: https://github.com/Arno0x/EmbedInHTML
        $string23 = /embedInHTML\.py/ nocase ascii wide
        // Description: What this tool does is taking a file (any type of file). encrypt it. and embed it into an HTML file as ressource. along with an automatic download routine simulating a user clicking on the embedded ressource.
        // Reference: https://github.com/Arno0x/EmbedInHTML
        $string24 = "EmbedInHTML-master" nocase ascii wide
        // Description: What this tool does is taking a file (any type of file). encrypt it. and embed it into an HTML file as ressource. along with an automatic download routine simulating a user clicking on the embedded ressource.
        // Reference: https://github.com/Arno0x/EmbedInHTML
        $string25 = /\-f\spayloads_examples\/calc\./ nocase ascii wide
        // Description: What this tool does is taking a file (any type of file). encrypt it. and embed it into an HTML file as ressource. along with an automatic download routine simulating a user clicking on the embedded ressource.
        // Reference: https://github.com/Arno0x/EmbedInHTML
        $string26 = /payloads_examples.{0,1000}calc\.js/ nocase ascii wide
        // Description: What this tool does is taking a file (any type of file). encrypt it. and embed it into an HTML file as ressource. along with an automatic download routine simulating a user clicking on the embedded ressource.
        // Reference: https://github.com/Arno0x/EmbedInHTML
        $string27 = /payloads_examples.{0,1000}calc\.xll/ nocase ascii wide

    condition:
        any of them
}
