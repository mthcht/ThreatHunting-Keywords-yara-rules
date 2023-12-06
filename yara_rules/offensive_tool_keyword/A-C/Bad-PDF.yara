rule Bad_PDF
{
    meta:
        description = "Detection patterns for the tool 'Bad-PDF' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Bad-PDF"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Bad-PDF create malicious PDF file to steal NTLM(NTLMv1/NTLMv2) Hashes from windows machines. it utilize vulnerability disclosed by checkpoint team to create the malicious PDF file. Bad-Pdf reads the NTLM hashes using Responder listener.
        // Reference: https://github.com/deepzec/Bad-Pdf
        $string1 = /Bad\-Pdf/ nocase ascii wide

    condition:
        any of them
}
