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
} from "@/components/ui/kibo-ui/code-block";
import FindingBadge from "../findings/finding-badge";


interface TCPLogDetailsCodeblockProps {
    language: string,
    filename: string,
    code: string
    findings?: FindingData[]
    streamIndex?: number
}

export default function TCPLogDetailsCodeblock(props: TCPLogDetailsCodeblockProps) {
    let codeData = Array({
        language: props.language,
        filename: props.filename,
        code: props.code,
    });

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
                {
                    props.streamIndex && 
                    <p className="text-sm font-bold">{props.streamIndex}</p>
                }
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
