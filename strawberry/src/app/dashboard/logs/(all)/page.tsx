import { DataTable } from "@/components/table/data-table";
import { constants } from "@/lib/constants"
import { columns } from "./columns";
import ChartRadarDefault, { MethodsStatsChartEntry } from "@/components/charts/methods-chart";

async function GetLogs(): Promise<ViewExtendedLogData[]> {
    const URL: string = `${constants.apiBaseURL}/logs`;
    const response: Response = await fetch(URL);
    const logs: ViewExtendedLogData[] = await response.json();
    return logs;
}

async function GetMethodsStatistics(): Promise<HTTPMethodStatistics> {
    const URL: string = `${constants.apiBaseURL}/logs/methods-stats`;
    const response: Response = await fetch(URL);
    const stats: HTTPMethodStatistics = await response.json();
    return stats;
}

export default async function LogsPage() {
    const logs: ViewExtendedLogData[] = await GetLogs();
    const stats: HTTPMethodStatistics = await GetMethodsStatistics();

    const chartData: MethodsStatsChartEntry[] = [
        {method: "GET", requests: stats.GET},
        {method: "HEAD", requests: stats.HEAD},
        {method: "OPTIONS", requests: stats.OPTIONS},
        {method: "TRACE", requests: stats.TRACE},
        {method: "PUT", requests: stats.PUT},
        {method: "DELETE", requests: stats.DELETE},
        {method: "POST", requests: stats.POST},
        {method: "PATCH", requests: stats.PATCH},
        {method: "CONNECT", requests: stats.CONNECT},
    ]

    return (
        <>
            <div className="flex flex-col lg:flex-row gap-4 flex-wrap">
                <div className="w-full lg:w-1/3 min-w-fit grow">
                    <ChartRadarDefault chartData={chartData} />
                </div>
                <div className="w-full lg:w-1/3 min-w-fit grow">
                    <p>Chart</p>
                </div>
                <div className="w-full lg:w-1/3 min-w-fit grow">
                    <p>Chart</p>
                </div>
            </div>

            <div>
                <DataTable columns={columns} title="HTTP Logs" data={logs} defaultColumn="httpMethod"/>
            </div>
        </>
    )
}