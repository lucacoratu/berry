import { cn } from "@/lib/utils";
import { Badge } from "../ui/badge";

import {
    HoverCard,
    HoverCardContent,
    HoverCardTrigger,
} from "@/components/ui/hover-card"
import { Separator } from "../ui/separator";
import { Button } from "../ui/button";
import { ShieldBan } from "lucide-react";
import { Tooltip, TooltipContent, TooltipTrigger } from "../ui/tooltip";

interface FindingBadgeProps {
    finding: FindingData
}

export default function FindingBadge(props: FindingBadgeProps) {
    const finding: FindingData = props.finding;

    //Based on the severity the color should differ
    let bg_color: string = "";
    switch (finding.severity) {
        case 1:
            bg_color = "bg-yellow-600";
            break;
        case 2:
            bg_color = "bg-orange-600";
            break;
        case 3:
            bg_color = "bg-red-600";
            break;
        default:
            bg_color = "";
            break;
    }

    return (
        <HoverCard>
            <HoverCardTrigger>
                <Badge className={cn(bg_color)}>
                    {finding.classification.toUpperCase()}
                </Badge>
            </HoverCardTrigger>
            <HoverCardContent side="top">
                <div className="text-xs flex flex-col gap-2">
                    <div className="flex flex-row justify-between items-center">
                        <p className="font-bold">Rule - {finding.ruleName}</p>
                        <Tooltip>
                            <TooltipTrigger asChild>
                                <Button variant="destructive" size="icon" className="w-6 h-6">
                                    <ShieldBan className="w-4 h-4" />
                                </Button>
                            </TooltipTrigger>
                            <TooltipContent>
                                <p>Disable rule</p>
                            </TooltipContent>
                        </Tooltip>
                    </div>

                    <Separator className="w-full h-2 bg-foreground/[0.8]" />

                    <div className="flex flex-col gap-1 text-justify">
                        <p>{finding.ruleDescription}</p>
                        <p>Matched string {finding.matchedString} on line {finding.line} at index {finding.lineIndex}</p>
                    </div>
                </div>
            </HoverCardContent>
        </HoverCard>
    );
}