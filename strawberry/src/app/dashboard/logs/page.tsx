import { DataTable } from "@/components/table/data-table";
import { constants } from "@/lib/constants"
import { columns } from "./columns";

async function GetLogs(): Promise<ViewExtendedLogData[]> {
    const URL: string = `${constants.apiBaseURL}/logs`;
    const response: Response = await fetch(URL);
    const agents: ViewExtendedLogData[] = await response.json();
    return agents;
}

export default async function LogsPage() {
    const logs: ViewExtendedLogData[] = await GetLogs();

    return (
        <>
            <div className="flex flex-row gap-4 flex-wrap">
                <div className="w-1/5 min-w-fit grow bg-card">
                    <p>Chart</p>
                </div>
                <div className="w-1/5 min-w-fit grow bg-card">
                    <p>Chart</p>
                </div>
                <div className="w-1/5 min-w-fit grow bg-card">
                    <p>Chart</p>
                </div>
            </div>

            <div>
                <DataTable columns={columns} title="Logs" data={logs} defaultColumn="httpMethod"/>
            </div>
        </>
    )
}