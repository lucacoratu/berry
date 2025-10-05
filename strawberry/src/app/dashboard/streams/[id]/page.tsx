import LogDetailsCodeblock from "@/components/codeblocks/logdetails";
import TCPLogDetailsCodeblock from "@/components/codeblocks/tcplogdetails";
import { constants } from "@/lib/constants";

async function GetStreamLogs(streamUUID: string) {
    const URL: string = `${constants.apiBaseURL}/streams/${streamUUID}/logs`;
    const response: Response = await fetch(URL);
    const streamLogs: ViewExtendedLogData[] = await response.json();
    return streamLogs;
}

export default async function LogDetailsPage({ params }: { params: { id: string } }) {
    const { id } = await params;

    const streamLogs: ViewExtendedLogData[] = await GetStreamLogs(id);

    return (
        <div className="flex flex-col gap-4">
            {
                streamLogs.map((logDetails: ViewExtendedLogData) => {
                    return (
                        (logDetails.request !== "" && <TCPLogDetailsCodeblock key={logDetails.streamIndex} language="http" filename="Ingress" code={logDetails.request} findings={logDetails.requestFindings} streamIndex={logDetails.streamIndex} />) ||
                        (logDetails.response !== "" && <TCPLogDetailsCodeblock key={logDetails.streamIndex} language="http" filename="Egress" code={logDetails.response} findings={logDetails.responseFindings} streamIndex={logDetails.streamIndex} />)
                    )
                })
            }
        </div>
    );
}