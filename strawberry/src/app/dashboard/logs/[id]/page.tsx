import LogDetailsCodeblock from "@/components/codeblocks/logdetails";
import { Button } from "@/components/ui/button";
import { constants } from "@/lib/constants";

async function GetLogDetails(logId: string): Promise<ViewExtendedLogData> {
    const URL: string = `${constants.apiBaseURL}/logs/${logId}`;
    const response: Response = await fetch(URL);
    const log: ViewExtendedLogData = await response.json();
    return log;
}

export default async function LogDetailsPage({ params }: { params: { id: string } }) {
    const { id } = await params;
    const logDetails: ViewExtendedLogData = await GetLogDetails(id);

    const highlightedLinesRequest: number[] = [...new Set(logDetails.requestFindings.map((findingData) => {
        return findingData.line;
    }))];

    return (
        <>
            <div className="flex flex-row">
                <Button size="sm">Copy Exploit</Button>
            </div>
            <div className="flex flex-col lg:flex-row gap-4">
                <LogDetailsCodeblock language="http" filename="Request" code={logDetails.request} highlightedLines={highlightedLinesRequest} findings={logDetails.requestFindings}/>
                <LogDetailsCodeblock language="http" filename="Response" code={logDetails.response} findings={logDetails.responseFindings}/>
            </div>
        </>
    );
}