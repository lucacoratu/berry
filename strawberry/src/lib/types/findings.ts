type FindingData = {
    ruleId: string
    ruleName: string,
    ruleDescription: string,
    line: number,
    lineIndex: number,
    length: number,
    matchedString: string,
    matchedBodyHash: string,
    matchedBodyHashAlg: string,
    classification: string,
    severity: number
}