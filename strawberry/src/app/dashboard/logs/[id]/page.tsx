import LogDetailsCodeblock from "@/components/codeblocks/logdetails";
import TCPLogDetailsCodeblock from "@/components/codeblocks/tcplogdetails";
import { Button } from "@/components/ui/button";
import { constants } from "@/lib/constants";
import Link from "next/link";

async function GetLogDetails(logId: string): Promise<ViewExtendedLogData> {
    const URL: string = `${constants.apiBaseURL}/logs/${logId}`;
    const response: Response = await fetch(URL);
    const log: ViewExtendedLogData = await response.json();
    return log;
}

export default async function LogDetailsPage({ params }: { params: { id: string } }) {
    const { id } = await params;
    const logDetails: ViewExtendedLogData = await GetLogDetails(id);

    let highlightedLinesRequest: number[] = [];
    if (logDetails.type === "http") {
        highlightedLinesRequest = [...new Set(logDetails.requestFindings.map((findingData) => {
            return findingData.line;
        }))];
    }

    return (
        <>
            <div className="flex flex-row gap-4">
                <Button size="sm">Copy Exploit</Button>
                {
                    logDetails.streamUUID !== "" &&
                    <Link href={`/dashboard/streams/${logDetails.streamUUID}`}> 
                        <Button size="sm">View Stream</Button>
                    </Link>
                }
            </div>

            {
                logDetails.type === "http" &&
                <div className="flex flex-col lg:flex-row gap-4">
                    <LogDetailsCodeblock language="http" filename="Request" code={logDetails.request} highlightedLines={highlightedLinesRequest} findings={logDetails.requestFindings} />
                    <LogDetailsCodeblock language="http" filename="Response" code={logDetails.response} findings={logDetails.responseFindings} />
                </div>
            }

            {
                logDetails.type === "tcp" &&
                (logDetails.request && <TCPLogDetailsCodeblock language="http" filename="Ingress" code={logDetails.request} findings={logDetails.requestFindings} />)
                ||
                (logDetails.response && <TCPLogDetailsCodeblock language="http" filename="Egress" code={logDetails.response} findings={logDetails.responseFindings} />)
            }
        </>
    );
}