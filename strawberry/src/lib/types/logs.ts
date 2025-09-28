type ViewExtendedLogData = {
    id: string,
    agentId: string,
    remoteIp: string,
    timestamp: number,
    type: 'http' | 'websocket' | 'tcp' | 'udp',
    request: string,
    response: string,
    requestFindings: FindingData[],
    responseFindings: FindingData[],
    verdict: string

    //Fields for HTTP type of log (this can be empty)
    httpMethod: string,
    httpRequestVersion: string,
    httpRequestURL: string,
    httpResponseVersion: string,
    httpResponseCode: string
}