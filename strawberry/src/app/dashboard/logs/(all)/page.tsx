import { DataTable } from "@/components/table/data-table";
import { constants } from "@/lib/constants"
import { columns } from "./columns";
import ChartRadarDefault, { MethodsStatsChartEntry } from "@/components/charts/methods-chart";
import { columnsTcp } from "./columns_tcp";

async function GetHTTPLogs(): Promise<ViewExtendedLogData[]> {
    const URL: string = `${constants.apiBaseURL}/logs/http`;
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

async function GetTCPLogs(): Promise<ViewExtendedLogData[]> {
    const URL: string = `${constants.apiBaseURL}/logs/tcp`;
    const response: Response = await fetch(URL);
    const logs: ViewExtendedLogData[] = await response.json();
    return logs;
}


export default async function LogsPage() {
    const httpLogs: ViewExtendedLogData[] = await GetHTTPLogs();
    const tcpLogs: ViewExtendedLogData[] = await GetTCPLogs();
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
    ];

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
                <DataTable columns={columns} title="HTTP Logs" data={httpLogs} defaultColumn="httpMethod"/>
            </div>

            <div>
                <DataTable columns={columnsTcp} title="TCP Logs" data={tcpLogs} defaultColumn="direction"/>
            </div>
        </>
    )
}