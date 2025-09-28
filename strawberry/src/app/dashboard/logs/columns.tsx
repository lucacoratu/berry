"use client";

import { Checkbox } from "@/components/ui/checkbox";

import { ColumnDef } from "@tanstack/react-table";
import { Power, Square, MoreHorizontal, Repeat, ArrowUpDown, Pencil, Trash } from "lucide-react";

import { Button } from "@/components/ui/button";
import {
    DropdownMenu,
    DropdownMenuContent,
    DropdownMenuItem,
    DropdownMenuLabel,
    DropdownMenuSeparator,
    DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { DataTableColumnHeader } from "@/components/table/column-header";
import Link from "next/link";
import FindingBadge from "@/components/findings/finding-badge";


export const columns: ColumnDef<ViewExtendedLogData>[] = [
    {
        id: "select",
        header: ({ table }) => (
            <Checkbox
                checked={
                    table.getIsAllPageRowsSelected() ||
                    (table.getIsSomePageRowsSelected() && "indeterminate")
                }
                onCheckedChange={(value) => table.toggleAllPageRowsSelected(!!value)}
                aria-label="Select all"
                className="mx-auto"
            />
        ),
        cell: ({ row }) => (
            <Checkbox
                checked={row.getIsSelected()}
                onCheckedChange={(value) => row.toggleSelected(!!value)}
                aria-label="Select row"
                className="mx-auto"
            />
        ),
        enableSorting: false,
        enableHiding: false,
    },
    {
        accessorKey: "remoteIp",
        header: ({ column }) => (
            <DataTableColumnHeader column={column} title="Remote IP" />
        ),
        cell: ({ row }) => {
            return (
                <p className="font-bold">{row.getValue('remoteIp')}</p>
            )
        }
    },
    {
        accessorKey: "httpMethod",
        header: ({ column }) => (
            <DataTableColumnHeader column={column} title="Method" />
        ),
    },
    {
        accessorKey: "httpRequestURL",
        header: ({ column }) => (
            <DataTableColumnHeader column={column} title="URL" />
        ),
        cell: ({ row }) => {
            return (
                <div className="truncate text-nowrap w-full max-w-[400px]">
                    {row.getValue('httpRequestURL')}
                </div>
            )
        }
    },
    {
        accessorKey: "httpResponseCode",
        header: ({ column }) => (
            <DataTableColumnHeader column={column} title="Response" />
        ),
    },
    {
        accessorKey: "timestamp",
        header: ({ column }) => (
            <DataTableColumnHeader column={column} title="Timestamp" />
        ),
        cell: ({ row }) => {
            const logDate = new Date(Number(row.getValue('timestamp')) * 1000);
            const date: string = logDate.toLocaleString('ro-RO').split(", ")[0];
            const time: string = logDate.toLocaleString('ro-RO').split(", ")[1];
            return (
                <div className="flex flex-col gap-1">
                    <p className="text-wrap text-center">{date}</p>
                    <p className="text-wrap text-center">{time} UTC</p>
                </div>
            );
        }
    },
    {
        accessorKey: "requestFindings",
        header: ({ column }) => (
            <DataTableColumnHeader column={column} title="Request Findings" />
        ),
        cell: ({ row }) => {
            const log = row.original;
            if (log.requestFindings != null) {
                return (
                    <div className="overflow-hidden justify-center flex flex-row gap-2 max-h-8">
                        {
                            log.requestFindings.map((finding: FindingData, index: number) => {
                                if (index < 3) {
                                    return (
                                        <FindingBadge key={index} finding={finding} />
                                    );
                                }
                            })
                        }
                    </div>
                );
            } else {
                return (
                    <>
                    </>
                );
            }
        }
    },
    {
        accessorKey: "responseFindings",
        header: ({ column }) => (
            <DataTableColumnHeader column={column} title="Response Findings" />
        ),
        cell: ({ row }) => {
            const log = row.original;
            //console.log(log);
            if (log.responseFindings != null) {
                return (
                    <div className="overflow-hidden flex flex-row gap-2 max-w-36 max-h-8">
                        response findings
                    </div>
                );
            } else {
                return (
                    <>
                    </>
                );
            }
        }
    },
    {
        id: "actions",
        header: "Actions",
        cell: ({ row }) => {
            const log = row.original

            return (
                <DropdownMenu>
                    <DropdownMenuTrigger asChild>
                        <Button variant="ghost" className="h-8 w-8 p-0 max-w-9">
                            <span className="sr-only">Open menu</span>
                            <MoreHorizontal className="h-4 w-4" />
                        </Button>
                    </DropdownMenuTrigger>
                    <DropdownMenuContent align="end" className="dark:bg-darksurface-100 dark:border-darksurface-400">
                        <DropdownMenuLabel>Actions</DropdownMenuLabel>
                        <DropdownMenuSeparator className="dark:bg-darksurface-400" />
                        <DropdownMenuItem className="dark:hover:bg-darksurface-400">
                            <Link href={`/dashboard/logs/${encodeURIComponent(log.id)}`}>
                                View Details
                            </Link>
                        </DropdownMenuItem>
                        <DropdownMenuSeparator className="dark:bg-darksurface-400" />
                        <DropdownMenuItem className="dark:hover:bg-darksurface-400">Copy Request</DropdownMenuItem>
                        <DropdownMenuItem className="dark:hover:bg-darksurface-400">Copy Response</DropdownMenuItem>
                        <DropdownMenuItem className="dark:hover:bg-darksurface-400">Copy Exploit Code</DropdownMenuItem>
                        <DropdownMenuSeparator className="dark:bg-darksurface-400" />
                        <DropdownMenuItem className="bg-red-600 dark:hover:bg-red-600/[0.8]">
                            Delete Log
                        </DropdownMenuItem>
                    </DropdownMenuContent>
                </DropdownMenu>
            )
        },
    },
];