"use client"

import { TrendingUp } from "lucide-react"
import { PolarAngleAxis, PolarGrid, Radar, RadarChart } from "recharts"

import {
    Card,
    CardContent,
    CardDescription,
    CardFooter,
    CardHeader,
    CardTitle,
} from "@/components/ui/card"
import {
    ChartConfig,
    ChartContainer,
    ChartTooltip,
    ChartTooltipContent,
} from "@/components/ui/chart"

export const description = "A radar chart"

// const chartData = [
//     { method: "January", requests: 186 },
//     { method: "February", requests: 305 },
//     { method: "March", requests: 237 },
//     { method: "April", requests: 273 },
//     { method: "May", requests: 209 },
//     { method: "June", requests: 214 },
// ]

const chartConfig = {
    requests: {
        label: "Requests",
        color: "var(--chart-1)",
    },
} satisfies ChartConfig

export type MethodsStatsChartEntry = {
    method: string,
    requests: number
}

interface HTTPMethodStatisticsChartProps {
    chartData: MethodsStatsChartEntry[]
}

export default function HTTPMethodStatisticsChart(props: HTTPMethodStatisticsChartProps) {
    return (
        <Card>
            <CardHeader className="items-center pb-4">
                <CardTitle>Methods Statistics</CardTitle>
                <CardDescription>
                    Number of requests for each HTTP method
                </CardDescription>
            </CardHeader>
            <CardContent className="pb-0">
                <ChartContainer
                    config={chartConfig}
                    className="mx-auto aspect-square max-h-[250px]"
                >
                    <RadarChart data={props.chartData}>
                        <ChartTooltip cursor={false} content={<ChartTooltipContent />} />
                        <PolarAngleAxis dataKey="method" />
                        <PolarGrid />
                        <Radar
                            dataKey="requests"
                            fill="var(--color-requests)"
                            fillOpacity={0.6}
                        />
                    </RadarChart>
                </ChartContainer>
            </CardContent>
        </Card>
    )
}
