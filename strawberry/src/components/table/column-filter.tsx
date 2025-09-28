"use client";

import { DropdownMenuTrigger } from "@radix-ui/react-dropdown-menu";
import { Filter } from "lucide-react";
import { Table } from "@tanstack/react-table";

import { Button } from "@/components/ui/button";
import {
    DropdownMenu,
    DropdownMenuCheckboxItem,
    DropdownMenuContent,
    DropdownMenuLabel,
    DropdownMenuSeparator,
} from "@/components/ui/dropdown-menu";
import { Input } from "@/components/ui/input";
import { useState } from "react";

interface DataTableFilterOptionsProps<TData> {
    table: Table<TData>
    defaultColumn: string
}

export function DataTableFilterOptions<TData>({
    table,
    defaultColumn
}: DataTableFilterOptionsProps<TData>) {

    const [selectedColumn, setSelectedColumn] = useState(defaultColumn);

    return (
        <>
            <DropdownMenu>
                <DropdownMenuTrigger asChild>
                    <Button variant="outline" size="default" className="hidden h-9 lg:flex">
                        <Filter className="mr-2 h-4 w-4" />
                        Columns
                    </Button>
                </DropdownMenuTrigger>
                <DropdownMenuContent align="center" className="w-[150px] border border-secondary">
                    <DropdownMenuLabel>Filter column</DropdownMenuLabel>
                    <DropdownMenuSeparator className="border border-secondary" />
                    {table
                        .getAllColumns()
                        .filter((column) => typeof column.accessorFn !== "undefined")
                        .map((column) => {
                            return (
                                <DropdownMenuCheckboxItem
                                    key={column.id}
                                    className="capitalize"
                                    checked={(column.id === defaultColumn && selectedColumn === "") || column.id === selectedColumn ? true : false}
                                    onCheckedChange={() => setSelectedColumn(column.id)}
                                >
                                    {column.id}
                                </DropdownMenuCheckboxItem>
                            )
                        })}
                </DropdownMenuContent>
            </DropdownMenu>
            <Input
                placeholder={"Filter " + selectedColumn + "..."}
                value={(table.getColumn(selectedColumn)?.getFilterValue() as string) ?? ""}
                onChange={(event) =>
                    table.getColumn(selectedColumn)?.setFilterValue(event.target.value)
                }
                className="max-w-lg border"
            />
        </>
    )
}