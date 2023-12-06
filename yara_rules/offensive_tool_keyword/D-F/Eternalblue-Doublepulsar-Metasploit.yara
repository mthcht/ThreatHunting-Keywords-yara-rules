rule Eternalblue_Doublepulsar_Metasploit
{
    meta:
        description = "Detection patterns for the tool 'Eternalblue-Doublepulsar-Metasploit' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Eternalblue-Doublepulsar-Metasploit"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: doublepulsa vulnerability exploit DoublePulsar is a backdoor implant tool developed by the U.S. National Security Agencys (NSA) Equation Group that was leaked by The Shadow Brokers in early 2017.[3] The tool infected more than 200.000 Microsoft Windows computers in only a few weeks.[4][5][3][6][7] and was used alongside EternalBlue in the May 2017 WannaCry ransomware attack.[8][9][10] A variant of DoublePulsar was first seen in the wild in March 2016. as discovered by Symantec. [11]
        // Reference: https://github.com/Telefonica/Eternalblue-Doublepulsar-Metasploit
        $string1 = /Eternalblue\-Doublepulsar/ nocase ascii wide

    condition:
        any of them
}
