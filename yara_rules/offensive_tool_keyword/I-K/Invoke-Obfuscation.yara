rule Invoke_Obfuscation
{
    meta:
        description = "Detection patterns for the tool 'Invoke-Obfuscation' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Invoke-Obfuscation"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Invoke-Obfuscation is a PowerShell v2.0+ compatible PowerShell command and script obfuscator.
        // Reference: https://github.com/danielbohannon/Invoke-Obfuscation
        $string1 = "\"Don't use this for evil, please\"" nocase ascii wide
        // Description: Invoke-Obfuscation is a PowerShell v2.0+ compatible PowerShell command and script obfuscator.
        // Reference: https://github.com/danielbohannon/Invoke-Obfuscation
        $string2 = /\/Invoke\-Obfuscation\.git/ nocase ascii wide
        // Description: Invoke-Obfuscation is a PowerShell v2.0+ compatible PowerShell command and script obfuscator.
        // Reference: https://github.com/danielbohannon/Invoke-Obfuscation
        $string3 = /\\Obfuscated_Command\.txt/ nocase ascii wide
        // Description: Invoke-Obfuscation is a PowerShell v2.0+ compatible PowerShell command and script obfuscator.
        // Reference: https://github.com/danielbohannon/Invoke-Obfuscation
        $string4 = "3615ddbae2c65e978aa8006c26b5c4a66c2e9433a1460b17ef700a39a708e5c1" nocase ascii wide
        // Description: Invoke-Obfuscation is a PowerShell v2.0+ compatible PowerShell command and script obfuscator.
        // Reference: https://github.com/danielbohannon/Invoke-Obfuscation
        $string5 = "40ce2ea4f4a90332a6e554ddbd9b801e22df018458127ae6ad1243c7d25a5523" nocase ascii wide
        // Description: Invoke-Obfuscation is a PowerShell v2.0+ compatible PowerShell command and script obfuscator.
        // Reference: https://github.com/danielbohannon/Invoke-Obfuscation
        $string6 = "46793c55c24e616a0d4eaaa0090b70bdde05e50c1b58da753d09063e6e838cc6" nocase ascii wide
        // Description: Invoke-Obfuscation is a PowerShell v2.0+ compatible PowerShell command and script obfuscator.
        // Reference: https://github.com/danielbohannon/Invoke-Obfuscation
        $string7 = "525bb5e67378b9bdc298aceb9e0108603741ae334e8ce748222999fcb2f1d818" nocase ascii wide
        // Description: Invoke-Obfuscation is a PowerShell v2.0+ compatible PowerShell command and script obfuscator.
        // Reference: https://github.com/danielbohannon/Invoke-Obfuscation
        $string8 = "5ed84b98241dd1db44e9e3beae6ec07ce8c64cd9200b73954617113578f91317" nocase ascii wide
        // Description: Invoke-Obfuscation is a PowerShell v2.0+ compatible PowerShell command and script obfuscator.
        // Reference: https://github.com/danielbohannon/Invoke-Obfuscation
        $string9 = "5fa4acad2bf202e61149a7f47189c4d60ac2823ea26d0f449912ab9d28ad0806" nocase ascii wide
        // Description: Invoke-Obfuscation is a PowerShell v2.0+ compatible PowerShell command and script obfuscator.
        // Reference: https://github.com/danielbohannon/Invoke-Obfuscation
        $string10 = "77c88d4c67b3600e78f82c938d2ef72525277647a27692b2114c9688bf1da121" nocase ascii wide
        // Description: Invoke-Obfuscation is a PowerShell v2.0+ compatible PowerShell command and script obfuscator.
        // Reference: https://github.com/danielbohannon/Invoke-Obfuscation
        $string11 = "9521883a37c093f31e9d3fde7d3293f637ea51ce573c3fa7967843b7e51d8dd0" nocase ascii wide
        // Description: Invoke-Obfuscation is a PowerShell v2.0+ compatible PowerShell command and script obfuscator.
        // Reference: https://github.com/danielbohannon/Invoke-Obfuscation
        $string12 = "9c409702151446f1eb8d951b45a902f2dbad1ebeacab9dd9beeaa5530e65ad0c" nocase ascii wide
        // Description: Invoke-Obfuscation is a PowerShell v2.0+ compatible PowerShell command and script obfuscator.
        // Reference: https://github.com/danielbohannon/Invoke-Obfuscation
        $string13 = "a10190903dfb52127ae37214a8c0124c68fc2f7fc91d0bae55eb9f556fa3c8dd" nocase ascii wide
        // Description: Invoke-Obfuscation is a PowerShell v2.0+ compatible PowerShell command and script obfuscator.
        // Reference: https://github.com/danielbohannon/Invoke-Obfuscation
        $string14 = "a83c33f484a2cbff3bbefdf51880714968930f69778e8921d8182d2b96e03314" nocase ascii wide
        // Description: Invoke-Obfuscation is a PowerShell v2.0+ compatible PowerShell command and script obfuscator.
        // Reference: https://github.com/danielbohannon/Invoke-Obfuscation
        $string15 = "abd9f4b93fc3f2bb0612bfbdef4e0da8797e985e7377ee0c08c2b5b5198c2743" nocase ascii wide
        // Description: Invoke-Obfuscation is a PowerShell v2.0+ compatible PowerShell command and script obfuscator.
        // Reference: https://github.com/danielbohannon/Invoke-Obfuscation
        $string16 = "c39d2a1c303847785a2a2af357dd948f5e6ec8194eb427c52a391db90de34f72" nocase ascii wide
        // Description: Invoke-Obfuscation is a PowerShell v2.0+ compatible PowerShell command and script obfuscator.
        // Reference: https://github.com/danielbohannon/Invoke-Obfuscation
        $string17 = "cecbe047e33d2dc3bc06cc7a62546a4e1a793d8da1dde4ba3aa021f944930d6d" nocase ascii wide
        // Description: Invoke-Obfuscation is a PowerShell v2.0+ compatible PowerShell command and script obfuscator.
        // Reference: https://github.com/danielbohannon/Invoke-Obfuscation
        $string18 = "d0a9150d-b6a4-4b17-a325-e3a24fed0aa9" nocase ascii wide
        // Description: Invoke-Obfuscation is a PowerShell v2.0+ compatible PowerShell command and script obfuscator.
        // Reference: https://github.com/danielbohannon/Invoke-Obfuscation
        $string19 = "d683205c9fad76e28a8e4cd0d72285e9a8573cc95c8b77f30186089459675817" nocase ascii wide
        // Description: Invoke-Obfuscation is a PowerShell v2.0+ compatible PowerShell command and script obfuscator.
        // Reference: https://github.com/danielbohannon/Invoke-Obfuscation
        $string20 = "danielbohannon/Invoke-Obfuscation" nocase ascii wide
        // Description: Invoke-Obfuscation is a PowerShell v2.0+ compatible PowerShell command and script obfuscator.
        // Reference: https://github.com/danielbohannon/Invoke-Obfuscation
        $string21 = "e403c105e8167585b1c431cdc86c943a8f93e876b3940668d088b976d8a1e9a2" nocase ascii wide
        // Description: Invoke-Obfuscation is a PowerShell v2.0+ compatible PowerShell command and script obfuscator.
        // Reference: https://github.com/danielbohannon/Invoke-Obfuscation
        $string22 = "Invoke-Obfuscation" nocase ascii wide
        // Description: Invoke-Obfuscation is a PowerShell v2.0+ compatible PowerShell command and script obfuscator.
        // Reference: https://github.com/danielbohannon/Invoke-Obfuscation
        $string23 = /Out\-CompressedCommand\.ps1/ nocase ascii wide
        // Description: Invoke-Obfuscation is a PowerShell v2.0+ compatible PowerShell command and script obfuscator.
        // Reference: https://github.com/danielbohannon/Invoke-Obfuscation
        $string24 = /Out\-EncodedAsciiCommand\.ps1/ nocase ascii wide
        // Description: Invoke-Obfuscation is a PowerShell v2.0+ compatible PowerShell command and script obfuscator.
        // Reference: https://github.com/danielbohannon/Invoke-Obfuscation
        $string25 = /Out\-EncodedBinaryCommand\.ps1/ nocase ascii wide
        // Description: Invoke-Obfuscation is a PowerShell v2.0+ compatible PowerShell command and script obfuscator.
        // Reference: https://github.com/danielbohannon/Invoke-Obfuscation
        $string26 = /Out\-EncodedBXORCommand\.ps1/ nocase ascii wide
        // Description: Invoke-Obfuscation is a PowerShell v2.0+ compatible PowerShell command and script obfuscator.
        // Reference: https://github.com/danielbohannon/Invoke-Obfuscation
        $string27 = /Out\-EncodedOctalCommand\.ps1/ nocase ascii wide
        // Description: Invoke-Obfuscation is a PowerShell v2.0+ compatible PowerShell command and script obfuscator.
        // Reference: https://github.com/danielbohannon/Invoke-Obfuscation
        $string28 = /Out\-EncodedSpecialCharOnlyCommand\.ps1/ nocase ascii wide
        // Description: Invoke-Obfuscation is a PowerShell v2.0+ compatible PowerShell command and script obfuscator.
        // Reference: https://github.com/danielbohannon/Invoke-Obfuscation
        $string29 = "Out-ObfuscatedArrayExpressionAst " nocase ascii wide
        // Description: Invoke-Obfuscation is a PowerShell v2.0+ compatible PowerShell command and script obfuscator.
        // Reference: https://github.com/danielbohannon/Invoke-Obfuscation
        $string30 = "Out-ObfuscatedArrayLiteralAst " nocase ascii wide
        // Description: Invoke-Obfuscation is a PowerShell v2.0+ compatible PowerShell command and script obfuscator.
        // Reference: https://github.com/danielbohannon/Invoke-Obfuscation
        $string31 = "Out-ObfuscatedAssignmentStatementAst " nocase ascii wide
        // Description: Invoke-Obfuscation is a PowerShell v2.0+ compatible PowerShell command and script obfuscator.
        // Reference: https://github.com/danielbohannon/Invoke-Obfuscation
        $string32 = /Out\-ObfuscatedAst\.ps1/ nocase ascii wide
        // Description: Invoke-Obfuscation is a PowerShell v2.0+ compatible PowerShell command and script obfuscator.
        // Reference: https://github.com/danielbohannon/Invoke-Obfuscation
        $string33 = "Out-ObfuscatedAstsReordered " nocase ascii wide
        // Description: Invoke-Obfuscation is a PowerShell v2.0+ compatible PowerShell command and script obfuscator.
        // Reference: https://github.com/danielbohannon/Invoke-Obfuscation
        $string34 = "Out-ObfuscatedAttributeAst " nocase ascii wide
        // Description: Invoke-Obfuscation is a PowerShell v2.0+ compatible PowerShell command and script obfuscator.
        // Reference: https://github.com/danielbohannon/Invoke-Obfuscation
        $string35 = "Out-ObfuscatedAttributeBaseAst " nocase ascii wide
        // Description: Invoke-Obfuscation is a PowerShell v2.0+ compatible PowerShell command and script obfuscator.
        // Reference: https://github.com/danielbohannon/Invoke-Obfuscation
        $string36 = "Out-ObfuscatedAttributedExpressionAst " nocase ascii wide
        // Description: Invoke-Obfuscation is a PowerShell v2.0+ compatible PowerShell command and script obfuscator.
        // Reference: https://github.com/danielbohannon/Invoke-Obfuscation
        $string37 = "Out-ObfuscatedBaseCtorInvokeMemberExpressionAst " nocase ascii wide
        // Description: Invoke-Obfuscation is a PowerShell v2.0+ compatible PowerShell command and script obfuscator.
        // Reference: https://github.com/danielbohannon/Invoke-Obfuscation
        $string38 = "Out-ObfuscatedBinaryExpressionAst " nocase ascii wide
        // Description: Invoke-Obfuscation is a PowerShell v2.0+ compatible PowerShell command and script obfuscator.
        // Reference: https://github.com/danielbohannon/Invoke-Obfuscation
        $string39 = "Out-ObfuscatedBlockStatementAst " nocase ascii wide
        // Description: Invoke-Obfuscation is a PowerShell v2.0+ compatible PowerShell command and script obfuscator.
        // Reference: https://github.com/danielbohannon/Invoke-Obfuscation
        $string40 = "Out-ObfuscatedBreakStatementAst " nocase ascii wide
        // Description: Invoke-Obfuscation is a PowerShell v2.0+ compatible PowerShell command and script obfuscator.
        // Reference: https://github.com/danielbohannon/Invoke-Obfuscation
        $string41 = "Out-ObfuscatedCatchClauseAst " nocase ascii wide
        // Description: Invoke-Obfuscation is a PowerShell v2.0+ compatible PowerShell command and script obfuscator.
        // Reference: https://github.com/danielbohannon/Invoke-Obfuscation
        $string42 = "Out-ObfuscatedChildrenAst " nocase ascii wide
        // Description: Invoke-Obfuscation is a PowerShell v2.0+ compatible PowerShell command and script obfuscator.
        // Reference: https://github.com/danielbohannon/Invoke-Obfuscation
        $string43 = "Out-ObfuscatedCommandAst " nocase ascii wide
        // Description: Invoke-Obfuscation is a PowerShell v2.0+ compatible PowerShell command and script obfuscator.
        // Reference: https://github.com/danielbohannon/Invoke-Obfuscation
        $string44 = "Out-ObfuscatedCommandBaseAst " nocase ascii wide
        // Description: Invoke-Obfuscation is a PowerShell v2.0+ compatible PowerShell command and script obfuscator.
        // Reference: https://github.com/danielbohannon/Invoke-Obfuscation
        $string45 = "Out-ObfuscatedCommandElementAst " nocase ascii wide
        // Description: Invoke-Obfuscation is a PowerShell v2.0+ compatible PowerShell command and script obfuscator.
        // Reference: https://github.com/danielbohannon/Invoke-Obfuscation
        $string46 = "Out-ObfuscatedCommandExpressionAst " nocase ascii wide
        // Description: Invoke-Obfuscation is a PowerShell v2.0+ compatible PowerShell command and script obfuscator.
        // Reference: https://github.com/danielbohannon/Invoke-Obfuscation
        $string47 = "Out-ObfuscatedCommandParameterAst " nocase ascii wide
        // Description: Invoke-Obfuscation is a PowerShell v2.0+ compatible PowerShell command and script obfuscator.
        // Reference: https://github.com/danielbohannon/Invoke-Obfuscation
        $string48 = "Out-ObfuscatedConfigurationDefinitionAst " nocase ascii wide
        // Description: Invoke-Obfuscation is a PowerShell v2.0+ compatible PowerShell command and script obfuscator.
        // Reference: https://github.com/danielbohannon/Invoke-Obfuscation
        $string49 = "Out-ObfuscatedConstantExpressionAst " nocase ascii wide
        // Description: Invoke-Obfuscation is a PowerShell v2.0+ compatible PowerShell command and script obfuscator.
        // Reference: https://github.com/danielbohannon/Invoke-Obfuscation
        $string50 = "Out-ObfuscatedContinueStatementAst " nocase ascii wide
        // Description: Invoke-Obfuscation is a PowerShell v2.0+ compatible PowerShell command and script obfuscator.
        // Reference: https://github.com/danielbohannon/Invoke-Obfuscation
        $string51 = "Out-ObfuscatedConvertExpressionAst " nocase ascii wide
        // Description: Invoke-Obfuscation is a PowerShell v2.0+ compatible PowerShell command and script obfuscator.
        // Reference: https://github.com/danielbohannon/Invoke-Obfuscation
        $string52 = "Out-ObfuscatedDataStatementAst " nocase ascii wide
        // Description: Invoke-Obfuscation is a PowerShell v2.0+ compatible PowerShell command and script obfuscator.
        // Reference: https://github.com/danielbohannon/Invoke-Obfuscation
        $string53 = "Out-ObfuscatedDoUntilStatementAst " nocase ascii wide
        // Description: Invoke-Obfuscation is a PowerShell v2.0+ compatible PowerShell command and script obfuscator.
        // Reference: https://github.com/danielbohannon/Invoke-Obfuscation
        $string54 = "Out-ObfuscatedDoWhileStatementAst " nocase ascii wide
        // Description: Invoke-Obfuscation is a PowerShell v2.0+ compatible PowerShell command and script obfuscator.
        // Reference: https://github.com/danielbohannon/Invoke-Obfuscation
        $string55 = "Out-ObfuscatedDynamicKeywordStatementAst " nocase ascii wide
        // Description: Invoke-Obfuscation is a PowerShell v2.0+ compatible PowerShell command and script obfuscator.
        // Reference: https://github.com/danielbohannon/Invoke-Obfuscation
        $string56 = "Out-ObfuscatedErrorExpressionAst " nocase ascii wide
        // Description: Invoke-Obfuscation is a PowerShell v2.0+ compatible PowerShell command and script obfuscator.
        // Reference: https://github.com/danielbohannon/Invoke-Obfuscation
        $string57 = "Out-ObfuscatedErrorStatementAst " nocase ascii wide
        // Description: Invoke-Obfuscation is a PowerShell v2.0+ compatible PowerShell command and script obfuscator.
        // Reference: https://github.com/danielbohannon/Invoke-Obfuscation
        $string58 = "Out-ObfuscatedExitStatementAst " nocase ascii wide
        // Description: Invoke-Obfuscation is a PowerShell v2.0+ compatible PowerShell command and script obfuscator.
        // Reference: https://github.com/danielbohannon/Invoke-Obfuscation
        $string59 = "Out-ObfuscatedExpandableStringExpressionAst " nocase ascii wide
        // Description: Invoke-Obfuscation is a PowerShell v2.0+ compatible PowerShell command and script obfuscator.
        // Reference: https://github.com/danielbohannon/Invoke-Obfuscation
        $string60 = "Out-ObfuscatedExpressionAst " nocase ascii wide
        // Description: Invoke-Obfuscation is a PowerShell v2.0+ compatible PowerShell command and script obfuscator.
        // Reference: https://github.com/danielbohannon/Invoke-Obfuscation
        $string61 = "Out-ObfuscatedFileRedirectionAst " nocase ascii wide
        // Description: Invoke-Obfuscation is a PowerShell v2.0+ compatible PowerShell command and script obfuscator.
        // Reference: https://github.com/danielbohannon/Invoke-Obfuscation
        $string62 = "Out-ObfuscatedForEachStatementAst " nocase ascii wide
        // Description: Invoke-Obfuscation is a PowerShell v2.0+ compatible PowerShell command and script obfuscator.
        // Reference: https://github.com/danielbohannon/Invoke-Obfuscation
        $string63 = "Out-ObfuscatedForStatementAst " nocase ascii wide
        // Description: Invoke-Obfuscation is a PowerShell v2.0+ compatible PowerShell command and script obfuscator.
        // Reference: https://github.com/danielbohannon/Invoke-Obfuscation
        $string64 = "Out-ObfuscatedFunctionDefinitionAst " nocase ascii wide
        // Description: Invoke-Obfuscation is a PowerShell v2.0+ compatible PowerShell command and script obfuscator.
        // Reference: https://github.com/danielbohannon/Invoke-Obfuscation
        $string65 = "Out-ObfuscatedFunctionMemberAst " nocase ascii wide
        // Description: Invoke-Obfuscation is a PowerShell v2.0+ compatible PowerShell command and script obfuscator.
        // Reference: https://github.com/danielbohannon/Invoke-Obfuscation
        $string66 = "Out-ObfuscatedHashtableAst " nocase ascii wide
        // Description: Invoke-Obfuscation is a PowerShell v2.0+ compatible PowerShell command and script obfuscator.
        // Reference: https://github.com/danielbohannon/Invoke-Obfuscation
        $string67 = "Out-ObfuscatedIfStatementAst " nocase ascii wide
        // Description: Invoke-Obfuscation is a PowerShell v2.0+ compatible PowerShell command and script obfuscator.
        // Reference: https://github.com/danielbohannon/Invoke-Obfuscation
        $string68 = "Out-ObfuscatedIndexExpressionAst " nocase ascii wide
        // Description: Invoke-Obfuscation is a PowerShell v2.0+ compatible PowerShell command and script obfuscator.
        // Reference: https://github.com/danielbohannon/Invoke-Obfuscation
        $string69 = "Out-ObfuscatedInvokeMemberExpressionAst " nocase ascii wide
        // Description: Invoke-Obfuscation is a PowerShell v2.0+ compatible PowerShell command and script obfuscator.
        // Reference: https://github.com/danielbohannon/Invoke-Obfuscation
        $string70 = "Out-ObfuscatedLabeledStatementAst " nocase ascii wide
        // Description: Invoke-Obfuscation is a PowerShell v2.0+ compatible PowerShell command and script obfuscator.
        // Reference: https://github.com/danielbohannon/Invoke-Obfuscation
        $string71 = "Out-ObfuscatedLoopStatementAst " nocase ascii wide
        // Description: Invoke-Obfuscation is a PowerShell v2.0+ compatible PowerShell command and script obfuscator.
        // Reference: https://github.com/danielbohannon/Invoke-Obfuscation
        $string72 = "Out-ObfuscatedMemberAst " nocase ascii wide
        // Description: Invoke-Obfuscation is a PowerShell v2.0+ compatible PowerShell command and script obfuscator.
        // Reference: https://github.com/danielbohannon/Invoke-Obfuscation
        $string73 = "Out-ObfuscatedMemberExpressionAst " nocase ascii wide
        // Description: Invoke-Obfuscation is a PowerShell v2.0+ compatible PowerShell command and script obfuscator.
        // Reference: https://github.com/danielbohannon/Invoke-Obfuscation
        $string74 = "Out-ObfuscatedMergingRedirectionAst " nocase ascii wide
        // Description: Invoke-Obfuscation is a PowerShell v2.0+ compatible PowerShell command and script obfuscator.
        // Reference: https://github.com/danielbohannon/Invoke-Obfuscation
        $string75 = "Out-ObfuscatedNamedAttributeArgumentAst " nocase ascii wide
        // Description: Invoke-Obfuscation is a PowerShell v2.0+ compatible PowerShell command and script obfuscator.
        // Reference: https://github.com/danielbohannon/Invoke-Obfuscation
        $string76 = "Out-ObfuscatedNamedBlockAst " nocase ascii wide
        // Description: Invoke-Obfuscation is a PowerShell v2.0+ compatible PowerShell command and script obfuscator.
        // Reference: https://github.com/danielbohannon/Invoke-Obfuscation
        $string77 = "Out-ObfuscatedParamBlockAst " nocase ascii wide
        // Description: Invoke-Obfuscation is a PowerShell v2.0+ compatible PowerShell command and script obfuscator.
        // Reference: https://github.com/danielbohannon/Invoke-Obfuscation
        $string78 = "Out-ObfuscatedParameterAst " nocase ascii wide
        // Description: Invoke-Obfuscation is a PowerShell v2.0+ compatible PowerShell command and script obfuscator.
        // Reference: https://github.com/danielbohannon/Invoke-Obfuscation
        $string79 = "Out-ObfuscatedParenExpressionAst " nocase ascii wide
        // Description: Invoke-Obfuscation is a PowerShell v2.0+ compatible PowerShell command and script obfuscator.
        // Reference: https://github.com/danielbohannon/Invoke-Obfuscation
        $string80 = "Out-ObfuscatedPipelineAst " nocase ascii wide
        // Description: Invoke-Obfuscation is a PowerShell v2.0+ compatible PowerShell command and script obfuscator.
        // Reference: https://github.com/danielbohannon/Invoke-Obfuscation
        $string81 = "Out-ObfuscatedPipelineBaseAst " nocase ascii wide
        // Description: Invoke-Obfuscation is a PowerShell v2.0+ compatible PowerShell command and script obfuscator.
        // Reference: https://github.com/danielbohannon/Invoke-Obfuscation
        $string82 = "Out-ObfuscatedPropertyMemberAst " nocase ascii wide
        // Description: Invoke-Obfuscation is a PowerShell v2.0+ compatible PowerShell command and script obfuscator.
        // Reference: https://github.com/danielbohannon/Invoke-Obfuscation
        $string83 = "Out-ObfuscatedRedirectionAst " nocase ascii wide
        // Description: Invoke-Obfuscation is a PowerShell v2.0+ compatible PowerShell command and script obfuscator.
        // Reference: https://github.com/danielbohannon/Invoke-Obfuscation
        $string84 = "Out-ObfuscatedReturnStatementAst " nocase ascii wide
        // Description: Invoke-Obfuscation is a PowerShell v2.0+ compatible PowerShell command and script obfuscator.
        // Reference: https://github.com/danielbohannon/Invoke-Obfuscation
        $string85 = "Out-ObfuscatedScriptBlockAst " nocase ascii wide
        // Description: Invoke-Obfuscation is a PowerShell v2.0+ compatible PowerShell command and script obfuscator.
        // Reference: https://github.com/danielbohannon/Invoke-Obfuscation
        $string86 = "Out-ObfuscatedScriptBlockExpressionAst " nocase ascii wide
        // Description: Invoke-Obfuscation is a PowerShell v2.0+ compatible PowerShell command and script obfuscator.
        // Reference: https://github.com/danielbohannon/Invoke-Obfuscation
        $string87 = "Out-ObfuscatedStatementAst " nocase ascii wide
        // Description: Invoke-Obfuscation is a PowerShell v2.0+ compatible PowerShell command and script obfuscator.
        // Reference: https://github.com/danielbohannon/Invoke-Obfuscation
        $string88 = "Out-ObfuscatedStatementBlockAst " nocase ascii wide
        // Description: Invoke-Obfuscation is a PowerShell v2.0+ compatible PowerShell command and script obfuscator.
        // Reference: https://github.com/danielbohannon/Invoke-Obfuscation
        $string89 = "Out-ObfuscatedStringCommand" nocase ascii wide
        // Description: Invoke-Obfuscation is a PowerShell v2.0+ compatible PowerShell command and script obfuscator.
        // Reference: https://github.com/danielbohannon/Invoke-Obfuscation
        $string90 = /Out\-ObfuscatedStringCommand\.ps1/ nocase ascii wide
        // Description: Invoke-Obfuscation is a PowerShell v2.0+ compatible PowerShell command and script obfuscator.
        // Reference: https://github.com/danielbohannon/Invoke-Obfuscation
        $string91 = "Out-ObfuscatedStringConstantExpressionAst " nocase ascii wide
        // Description: Invoke-Obfuscation is a PowerShell v2.0+ compatible PowerShell command and script obfuscator.
        // Reference: https://github.com/danielbohannon/Invoke-Obfuscation
        $string92 = "Out-ObfuscatedSubExpressionAst " nocase ascii wide
        // Description: Invoke-Obfuscation is a PowerShell v2.0+ compatible PowerShell command and script obfuscator.
        // Reference: https://github.com/danielbohannon/Invoke-Obfuscation
        $string93 = "Out-ObfuscatedSwitchStatementAst " nocase ascii wide
        // Description: Invoke-Obfuscation is a PowerShell v2.0+ compatible PowerShell command and script obfuscator.
        // Reference: https://github.com/danielbohannon/Invoke-Obfuscation
        $string94 = "Out-ObfuscatedThrowStatementAst " nocase ascii wide
        // Description: Invoke-Obfuscation is a PowerShell v2.0+ compatible PowerShell command and script obfuscator.
        // Reference: https://github.com/danielbohannon/Invoke-Obfuscation
        $string95 = "Out-ObfuscatedTokenCommand" nocase ascii wide
        // Description: Invoke-Obfuscation is a PowerShell v2.0+ compatible PowerShell command and script obfuscator.
        // Reference: https://github.com/danielbohannon/Invoke-Obfuscation
        $string96 = /Out\-ObfuscatedTokenCommand\.ps1/ nocase ascii wide
        // Description: Invoke-Obfuscation is a PowerShell v2.0+ compatible PowerShell command and script obfuscator.
        // Reference: https://github.com/danielbohannon/Invoke-Obfuscation
        $string97 = "Out-ObfuscatedTrapStatementAst " nocase ascii wide
        // Description: Invoke-Obfuscation is a PowerShell v2.0+ compatible PowerShell command and script obfuscator.
        // Reference: https://github.com/danielbohannon/Invoke-Obfuscation
        $string98 = "Out-ObfuscatedTryStatementAst " nocase ascii wide
        // Description: Invoke-Obfuscation is a PowerShell v2.0+ compatible PowerShell command and script obfuscator.
        // Reference: https://github.com/danielbohannon/Invoke-Obfuscation
        $string99 = "Out-ObfuscatedTypeConstraintAst " nocase ascii wide
        // Description: Invoke-Obfuscation is a PowerShell v2.0+ compatible PowerShell command and script obfuscator.
        // Reference: https://github.com/danielbohannon/Invoke-Obfuscation
        $string100 = "Out-ObfuscatedTypeDefinitionAst " nocase ascii wide
        // Description: Invoke-Obfuscation is a PowerShell v2.0+ compatible PowerShell command and script obfuscator.
        // Reference: https://github.com/danielbohannon/Invoke-Obfuscation
        $string101 = "Out-ObfuscatedTypeExpressionAst " nocase ascii wide
        // Description: Invoke-Obfuscation is a PowerShell v2.0+ compatible PowerShell command and script obfuscator.
        // Reference: https://github.com/danielbohannon/Invoke-Obfuscation
        $string102 = "Out-ObfuscatedUnaryExpressionAst " nocase ascii wide
        // Description: Invoke-Obfuscation is a PowerShell v2.0+ compatible PowerShell command and script obfuscator.
        // Reference: https://github.com/danielbohannon/Invoke-Obfuscation
        $string103 = "Out-ObfuscatedUsingExpressionAst " nocase ascii wide
        // Description: Invoke-Obfuscation is a PowerShell v2.0+ compatible PowerShell command and script obfuscator.
        // Reference: https://github.com/danielbohannon/Invoke-Obfuscation
        $string104 = "Out-ObfuscatedUsingStatementAst " nocase ascii wide
        // Description: Invoke-Obfuscation is a PowerShell v2.0+ compatible PowerShell command and script obfuscator.
        // Reference: https://github.com/danielbohannon/Invoke-Obfuscation
        $string105 = "Out-ObfuscatedVariableExpressionAst " nocase ascii wide
        // Description: Invoke-Obfuscation is a PowerShell v2.0+ compatible PowerShell command and script obfuscator.
        // Reference: https://github.com/danielbohannon/Invoke-Obfuscation
        $string106 = "Out-ObfuscatedWhileStatementAst " nocase ascii wide

    condition:
        any of them
}
