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
        $string1 = /\.py\s\s\-k\s.*\s\-f\s.*\.bat\s\-o\s.*\.html/ nocase ascii wide
        // Description: What this tool does is taking a file (any type of file). encrypt it. and embed it into an HTML file as ressource. along with an automatic download routine simulating a user clicking on the embedded ressource.
        // Reference: https://github.com/Arno0x/EmbedInHTML
        $string2 = /\.py\s\s\-k\s.*\s\-f\s.*\.docm\s\-o\s.*\.html/ nocase ascii wide
        // Description: What this tool does is taking a file (any type of file). encrypt it. and embed it into an HTML file as ressource. along with an automatic download routine simulating a user clicking on the embedded ressource.
        // Reference: https://github.com/Arno0x/EmbedInHTML
        $string3 = /\.py\s\s\-k\s.*\s\-f\s.*\.docx\s\-o\s.*\.html/ nocase ascii wide
        // Description: What this tool does is taking a file (any type of file). encrypt it. and embed it into an HTML file as ressource. along with an automatic download routine simulating a user clicking on the embedded ressource.
        // Reference: https://github.com/Arno0x/EmbedInHTML
        $string4 = /\.py\s\s\-k\s.*\s\-f\s.*\.exe\s\-o\s.*\.html/ nocase ascii wide
        // Description: What this tool does is taking a file (any type of file). encrypt it. and embed it into an HTML file as ressource. along with an automatic download routine simulating a user clicking on the embedded ressource.
        // Reference: https://github.com/Arno0x/EmbedInHTML
        $string5 = /\.py\s\s\-k\s.*\s\-f\s.*\.js\s\-o\s.*\.html/ nocase ascii wide
        // Description: What this tool does is taking a file (any type of file). encrypt it. and embed it into an HTML file as ressource. along with an automatic download routine simulating a user clicking on the embedded ressource.
        // Reference: https://github.com/Arno0x/EmbedInHTML
        $string6 = /\.py\s\s\-k\s.*\s\-f\s.*\.pps\s\-o\s.*\.html/ nocase ascii wide
        // Description: What this tool does is taking a file (any type of file). encrypt it. and embed it into an HTML file as ressource. along with an automatic download routine simulating a user clicking on the embedded ressource.
        // Reference: https://github.com/Arno0x/EmbedInHTML
        $string7 = /\.py\s\s\-k\s.*\s\-f\s.*\.ppsx\s\-o\s.*\.html/ nocase ascii wide
        // Description: What this tool does is taking a file (any type of file). encrypt it. and embed it into an HTML file as ressource. along with an automatic download routine simulating a user clicking on the embedded ressource.
        // Reference: https://github.com/Arno0x/EmbedInHTML
        $string8 = /\.py\s\s\-k\s.*\s\-f\s.*\.ppt\s\-o\s.*\.html/ nocase ascii wide
        // Description: What this tool does is taking a file (any type of file). encrypt it. and embed it into an HTML file as ressource. along with an automatic download routine simulating a user clicking on the embedded ressource.
        // Reference: https://github.com/Arno0x/EmbedInHTML
        $string9 = /\.py\s\s\-k\s.*\s\-f\s.*\.ps1\s\-o\s.*\.html/ nocase ascii wide
        // Description: What this tool does is taking a file (any type of file). encrypt it. and embed it into an HTML file as ressource. along with an automatic download routine simulating a user clicking on the embedded ressource.
        // Reference: https://github.com/Arno0x/EmbedInHTML
        $string10 = /\.py\s\s\-k\s.*\s\-f\s.*\.xll\s\-o\s.*\.html/ nocase ascii wide
        // Description: What this tool does is taking a file (any type of file). encrypt it. and embed it into an HTML file as ressource. along with an automatic download routine simulating a user clicking on the embedded ressource.
        // Reference: https://github.com/Arno0x/EmbedInHTML
        $string11 = /\.py\s\s\-k\s.*\s\-f\s.*\.xls\s\-o\s.*\.html/ nocase ascii wide
        // Description: What this tool does is taking a file (any type of file). encrypt it. and embed it into an HTML file as ressource. along with an automatic download routine simulating a user clicking on the embedded ressource.
        // Reference: https://github.com/Arno0x/EmbedInHTML
        $string12 = /\.py\s\s\-k\s.*\s\-f\s.*\.xlsb\s\-o\s.*\.html/ nocase ascii wide
        // Description: What this tool does is taking a file (any type of file). encrypt it. and embed it into an HTML file as ressource. along with an automatic download routine simulating a user clicking on the embedded ressource.
        // Reference: https://github.com/Arno0x/EmbedInHTML
        $string13 = /\.py\s\s\-k\s.*\s\-f\s.*\.xlsm\s\-o\s.*\.html/ nocase ascii wide
        // Description: What this tool does is taking a file (any type of file). encrypt it. and embed it into an HTML file as ressource. along with an automatic download routine simulating a user clicking on the embedded ressource.
        // Reference: https://github.com/Arno0x/EmbedInHTML
        $string14 = /\.py\s\s\-k\s.*\s\-f\s.*\.xlsx\s\-o\s.*\.html/ nocase ascii wide
        // Description: What this tool does is taking a file (any type of file). encrypt it. and embed it into an HTML file as ressource. along with an automatic download routine simulating a user clicking on the embedded ressource.
        // Reference: https://github.com/Arno0x/EmbedInHTML
        $string15 = /\.py\s\-k\s.*\s\-f\s.*\.doc\s\-o\s.*\.html/ nocase ascii wide
        // Description: What this tool does is taking a file (any type of file). encrypt it. and embed it into an HTML file as ressource. along with an automatic download routine simulating a user clicking on the embedded ressource.
        // Reference: https://github.com/Arno0x/EmbedInHTML
        $string16 = /\/agent\/stagers\/dropbox\.py/ nocase ascii wide
        // Description: What this tool does is taking a file (any type of file). encrypt it. and embed it into an HTML file as ressource. along with an automatic download routine simulating a user clicking on the embedded ressource.
        // Reference: https://github.com/Arno0x/EmbedInHTML
        $string17 = /\/EmbedInHTML\.git/ nocase ascii wide
        // Description: What this tool does is taking a file (any type of file). encrypt it. and embed it into an HTML file as ressource. along with an automatic download routine simulating a user clicking on the embedded ressource.
        // Reference: https://github.com/Arno0x/EmbedInHTML
        $string18 = /\/EmbedInHTML\// nocase ascii wide
        // Description: What this tool does is taking a file (any type of file). encrypt it. and embed it into an HTML file as ressource. along with an automatic download routine simulating a user clicking on the embedded ressource.
        // Reference: https://github.com/Arno0x/EmbedInHTML
        $string19 = /Arno0x\/EmbedInHTML/ nocase ascii wide
        // Description: What this tool does is taking a file (any type of file). encrypt it. and embed it into an HTML file as ressource. along with an automatic download routine simulating a user clicking on the embedded ressource.
        // Reference: https://github.com/Arno0x/EmbedInHTML
        $string20 = /embedInHTML\.html/ nocase ascii wide
        // Description: What this tool does is taking a file (any type of file). encrypt it. and embed it into an HTML file as ressource. along with an automatic download routine simulating a user clicking on the embedded ressource.
        // Reference: https://github.com/Arno0x/EmbedInHTML
        $string21 = /embedInHTML\.py/ nocase ascii wide
        // Description: What this tool does is taking a file (any type of file). encrypt it. and embed it into an HTML file as ressource. along with an automatic download routine simulating a user clicking on the embedded ressource.
        // Reference: https://github.com/Arno0x/EmbedInHTML
        $string22 = /EmbedInHTML\-master/ nocase ascii wide
        // Description: What this tool does is taking a file (any type of file). encrypt it. and embed it into an HTML file as ressource. along with an automatic download routine simulating a user clicking on the embedded ressource.
        // Reference: https://github.com/Arno0x/EmbedInHTML
        $string23 = /\-f\spayloads_examples\/calc\./ nocase ascii wide
        // Description: What this tool does is taking a file (any type of file). encrypt it. and embed it into an HTML file as ressource. along with an automatic download routine simulating a user clicking on the embedded ressource.
        // Reference: https://github.com/Arno0x/EmbedInHTML
        $string24 = /payloads_examples.*calc\.js/ nocase ascii wide
        // Description: What this tool does is taking a file (any type of file). encrypt it. and embed it into an HTML file as ressource. along with an automatic download routine simulating a user clicking on the embedded ressource.
        // Reference: https://github.com/Arno0x/EmbedInHTML
        $string25 = /payloads_examples.*calc\.xll/ nocase ascii wide

    condition:
        any of them
}