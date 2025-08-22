import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { constants } from "@/lib/constants"

async function GetAgents(): Promise<ViewAgentResponse[]> {
    const URL: string = `${constants.apiBaseURL}/agents`;
    const response: Response = await fetch(URL);
    const agents: ViewAgentResponse[] = await response.json();
    return agents;
}

export default async function AgentsPage() {
    const agents: ViewAgentResponse[] = await GetAgents();
    return (
        <div className="flex flex-row gap-2">
            {
                agents && agents.map((agent) => {
                    return (
                        <Card key={agent.id} className="min-w-96 w-1/4 rounded-lg hover:shadow-lg">
                            <CardHeader>
                                <CardTitle>{agent.name || "No name"}</CardTitle>
                                <CardDescription className="text-xs">
                                    <div className="flex flex-row items-center gap-2">
                                        <p>SQL ID:</p>
                                        <p>{agent.id}</p>
                                    </div>
                                    <div className="flex flex-row items-center gap-2">
                                        <p>UUID:</p>
                                        <p>{agent.uuid}</p>
                                    </div>
                                </CardDescription>
                                <CardContent className="pl-0 text-sm w-full">
                                    <div className="flex flex-row items-center gap-2">
                                        <p>Logs collected:</p>
                                        <p>{agent.logsCollected || 0}</p>
                                    </div>
                                </CardContent>
                            </CardHeader>
                        </Card>
                    )
                })
            }
        </div>
    )
}