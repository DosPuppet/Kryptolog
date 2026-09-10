import { FileText, Download } from 'lucide-react';
import { formatSize } from '../../utils/format';
import { readFileDescriptor } from '../../utils/secretContent';

// The decrypted body of a secret: a file list, or the text itself.
//
// Rendered identically by the list and grid cards, which previously carried two
// copies of it. `onDownload` is passed rather than assumed because the two file
// shapes are fetched differently: a multi-file entry already holds its own blob
// URL, while a single file is rebuilt from the descriptor.
export default function SecretContentPane({ content, onDownload }) {
    const descriptor = readFileDescriptor(content);

    if (!descriptor) {
        return <span className="whitespace-pre-wrap break-words">{content}</span>;
    }

    return (
        <div className="flex flex-col gap-2">
            {descriptor.multiple && (
                <div className="text-xs text-slate-500 mb-1">{descriptor.files.length} files</div>
            )}
            {descriptor.files.map((file, idx) => {
                const isImage = file.mime && file.mime.startsWith('image/');
                return (
                    <div key={file.name ?? idx} className="flex flex-col gap-1">
                        <div className="flex items-center gap-2 text-indigo-300">
                            <FileText className="w-4 h-4" />
                            <span className="font-medium">{file.name}</span>
                            <span className="text-xs text-slate-500">
                                ({file.mime}{file.size ? ` · ${formatSize(file.size)}` : ''})
                            </span>
                            {descriptor.multiple && (
                                <a
                                    href={file.content}
                                    download={file.name}
                                    className="flex items-center gap-1 px-2 py-1 bg-indigo-600 hover:bg-indigo-500 text-white rounded text-xs transition-colors ml-auto"
                                >
                                    <Download className="w-3 h-3" /> Download
                                </a>
                            )}
                        </div>
                        {isImage && (
                            <img
                                src={file.content}
                                alt={file.name}
                                className={`${descriptor.multiple ? 'max-h-32 ml-6' : 'max-h-48'} max-w-xs rounded-lg border border-slate-700 object-contain`}
                            />
                        )}
                    </div>
                );
            })}
            {!descriptor.multiple && (
                <button
                    onClick={() => onDownload(content)}
                    className="flex items-center gap-2 px-3 py-2 bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg text-sm w-fit transition-colors"
                >
                    <Download className="w-4 h-4" /> Download File
                </button>
            )}
        </div>
    );
}
