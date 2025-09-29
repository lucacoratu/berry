"use client";

import type { BundledLanguage } from "@/components/ui/kibo-ui/code-block";
import {
    CodeBlock,
    CodeBlockBody,
    CodeBlockContent,
    CodeBlockCopyButton,
    CodeBlockFilename,
    CodeBlockFiles,
    CodeBlockHeader,
    CodeBlockItem,
    CodeBlockSelect,
    CodeBlockSelectContent,
    CodeBlockSelectItem,
    CodeBlockSelectTrigger,
    CodeBlockSelectValue,
} from "@/components/ui/kibo-ui/code-block";
import FindingBadge from "../findings/finding-badge";


interface LogDetailsCodeblockProps {
    language: string,
    filename: string,
    code: string
    highlightedLines?: number[]
    findings?: FindingData[]
}

export default function LogDetailsCodeblock(props: LogDetailsCodeblockProps) {
    const lineHighlightText = ' // [!code highlight]';

    let codeData = Array({
        language: props.language,
        filename: props.filename,
        code: props.code,
    });

    if (props.highlightedLines) {
        const splitCode = props.code.split('\n');

        let newCode = '';

        for (let i = 0; i < splitCode.length; i++) {
            let line = splitCode[i];
            if (props.highlightedLines.includes(i))
                line += lineHighlightText;
            newCode += line + "\n";
        }

        codeData[0].code = newCode;
    }



    return (
        <CodeBlock data={codeData} defaultValue={props.language}>
            <CodeBlockHeader>
                <CodeBlockFiles>
                    {(item) => (
                        <CodeBlockFilename key={item.language} value={item.language}>
                            <p key={item.filename} className="font-bold">{item.filename}</p>
                        </CodeBlockFilename>
                    )}
                </CodeBlockFiles>
                <div className="flex flex-row gap-2 items-center mr-5">
                    {
                        props.findings && props.findings.map((findingData, index) => {
                            return (
                                <FindingBadge key={index} finding={findingData} />
                            );
                        })
                    }
                </div>
                <CodeBlockCopyButton
                    onCopy={() => console.log("Copied code to clipboard")}
                    onError={() => console.error("Failed to copy code to clipboard")}
                />
            </CodeBlockHeader>
            <CodeBlockBody>
                {(item) => (
                    <CodeBlockItem key={item.language} value={item.language}>
                        <CodeBlockContent language={item.language as BundledLanguage}>
                            {item.code}
                        </CodeBlockContent>
                    </CodeBlockItem>
                )}
            </CodeBlockBody>
        </CodeBlock>
    );
};
