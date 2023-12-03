rule AWS_Loot
{
    meta:
        description = "Detection patterns for the tool 'AWS-Loot' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "AWS-Loot"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Searches an AWS environment looking for secrets. by enumerating environment variables and source code. This tool allows quick enumeration over large sets of AWS instances and services.
        // Reference: https://github.com/sebastian-mora/AWS-Loot
        $string1 = /.{0,1000}\sawsloot\.py.{0,1000}/ nocase ascii wide
        // Description: Searches an AWS environment looking for secrets. by enumerating environment variables and source code. This tool allows quick enumeration over large sets of AWS instances and services.
        // Reference: https://github.com/sebastian-mora/AWS-Loot
        $string2 = /.{0,1000}\.\/awsloot\s.{0,1000}/ nocase ascii wide
        // Description: Searches an AWS environment looking for secrets. by enumerating environment variables and source code. This tool allows quick enumeration over large sets of AWS instances and services.
        // Reference: https://github.com/sebastian-mora/AWS-Loot
        $string3 = /.{0,1000}\.\/awsloot\.py.{0,1000}/ nocase ascii wide
        // Description: Searches an AWS environment looking for secrets. by enumerating environment variables and source code. This tool allows quick enumeration over large sets of AWS instances and services.
        // Reference: https://github.com/sebastian-mora/AWS-Loot
        $string4 = /.{0,1000}\/AWS\-Loot.{0,1000}/ nocase ascii wide
        // Description: Searches an AWS environment looking for secrets. by enumerating environment variables and source code. This tool allows quick enumeration over large sets of AWS instances and services.
        // Reference: https://github.com/sebastian-mora/AWS-Loot
        $string5 = /.{0,1000}\/CodeBuildLooter\.py.{0,1000}/ nocase ascii wide
        // Description: Searches an AWS environment looking for secrets. by enumerating environment variables and source code. This tool allows quick enumeration over large sets of AWS instances and services.
        // Reference: https://github.com/sebastian-mora/AWS-Loot
        $string6 = /.{0,1000}\/EC2Looter\.py.{0,1000}/ nocase ascii wide
        // Description: Searches an AWS environment looking for secrets. by enumerating environment variables and source code. This tool allows quick enumeration over large sets of AWS instances and services.
        // Reference: https://github.com/sebastian-mora/AWS-Loot
        $string7 = /.{0,1000}\/LambdaLooter\.py.{0,1000}/ nocase ascii wide
        // Description: Searches an AWS environment looking for secrets. by enumerating environment variables and source code. This tool allows quick enumeration over large sets of AWS instances and services.
        // Reference: https://github.com/sebastian-mora/AWS-Loot
        $string8 = /.{0,1000}awsloot\.py\s.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
