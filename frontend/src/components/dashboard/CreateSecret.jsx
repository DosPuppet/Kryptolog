import { useState } from 'react';
import { useAuth } from '../../context/AuthContext';
import { Loader2, Plus, PenTool, Upload, FileText, Check, Shield, Trash2 } from 'lucide-react';

const CreateSecret = ({ onCreate, onCancel }) => {
    const { authType } = useAuth();

    // Form State
    const [name, setName] = useState('');
    const [contentType, setContentType] = useState('text'); // 'text' | 'file'
    const [content, setContent] = useState('');
    const [selectedFiles, setSelectedFiles] = useState([]);
    const [isSigned, setIsSigned] = useState(false);
    const [creating, setCreating] = useState(false);
    const [isDragging, setIsDragging] = useState(false);

    const handleDragOver = (e) => { e.preventDefault(); e.stopPropagation(); };
    const handleDragEnter = (e) => { e.preventDefault(); e.stopPropagation(); setIsDragging(true); setContentType('file'); };
    const handleDragLeave = (e) => { e.preventDefault(); e.stopPropagation(); if (!e.currentTarget.contains(e.relatedTarget)) setIsDragging(false); };
    const handleDrop = (e) => {
        e.preventDefault(); e.stopPropagation(); setIsDragging(false);
        const droppedFiles = Array.from(e.dataTransfer?.files || []);
        if (droppedFiles.length) { setSelectedFiles(prev => [...prev, ...droppedFiles]); setContentType('file'); }
    };
    const handleFileInput = (e) => {
        const newFiles = Array.from(e.target.files || []);
        if (newFiles.length) setSelectedFiles(prev => [...prev, ...newFiles]);
        e.target.value = ''; // reset to allow re-selecting same file
    };
    const removeFile = (index) => setSelectedFiles(prev => prev.filter((_, i) => i !== index));
    const formatSize = (bytes) => bytes < 1024 ? `${bytes} B` : bytes < 1024 * 1024 ? `${(bytes / 1024).toFixed(1)} KB` : `${(bytes / (1024 * 1024)).toFixed(1)} MB`;

    const MAX_FILE_SIZE = 50 * 1024 * 1024; // 50MB (chunked upload supports larger files)

    const handleSubmit = async (e) => {
        e.preventDefault();
        setCreating(true);

        try {
            // Validation
            if (!name) {
                alert("Please enter a name.");
                setCreating(false);
                return;
            }
            if (contentType === 'text' && !content) {
                alert("Please enter content.");
                setCreating(false);
                return;
            }
            if (contentType === 'file' && selectedFiles.length === 0) {
                alert("Please select at least one file.");
                setCreating(false);
                return;
            }

            if (contentType === 'file') {
                const oversized = selectedFiles.find(f => f.size > MAX_FILE_SIZE);
                if (oversized) {
                    alert(`File "${oversized.name}" is too large (Max 50MB per file).`);
                    setCreating(false);
                    return;
                }
                await onCreate(
                    name,
                    isSigned ? 'signed_document' : 'file',
                    '',
                    isSigned,
                    selectedFiles
                );
            } else {
                await onCreate(name, isSigned ? 'signed_document' : 'standard', content, isSigned);
            }

            onCancel();
        } catch (error) {
            console.error(error);
            alert("Creation failed: " + error.message);
        } finally {
            setCreating(false);
        }
    };

    return (
        <div className="bg-white dark:bg-slate-850 border border-slate-200 dark:border-slate-700 rounded-xl p-6 mb-6 shadow-lg animate-in fade-in slide-in-from-top-4">
            <div className="flex justify-between items-center mb-6">
                <h3 className="text-lg font-bold text-slate-900 dark:text-white flex items-center gap-2">
                    <Plus className="w-5 h-5 text-indigo-500" /> Create New Secret
                </h3>
            </div>

            <form onSubmit={handleSubmit} className="space-y-4">
                <div>
                    <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">Name</label>
                    <input
                        type="text"
                        value={name}
                        onChange={e => setName(e.target.value)}
                        className="w-full bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded-lg px-4 py-2 text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-indigo-500"
                        placeholder="e.g. My WiFi Password"
                        disabled={creating}
                    />
                </div>

                {/* Type Selection */}
                <div className="flex p-1 bg-slate-100 dark:bg-slate-750 rounded-lg w-full sm:w-fit">
                    <button
                        type="button"
                        onClick={() => setContentType('text')}
                        className={`flex-1 sm:flex-none px-4 py-2 rounded-md text-sm font-medium transition-all ${contentType === 'text' ? 'bg-white dark:bg-slate-700 text-indigo-600 dark:text-white shadow-sm' : 'text-slate-500 hover:text-slate-700 dark:hover:text-slate-300'}`}
                    >
                        <div className="flex items-center gap-2 justify-center">
                            <PenTool className="w-4 h-4" /> Text
                        </div>
                    </button>
                    <button
                        type="button"
                        onClick={() => setContentType('file')}
                        className={`flex-1 sm:flex-none px-4 py-2 rounded-md text-sm font-medium transition-all ${contentType === 'file' ? 'bg-white dark:bg-slate-700 text-indigo-600 dark:text-white shadow-sm' : 'text-slate-500 hover:text-slate-700 dark:hover:text-slate-300'}`}
                    >
                        <div className="flex items-center gap-2 justify-center">
                            <Upload className="w-4 h-4" /> File
                        </div>
                    </button>
                </div>

                {contentType === 'text' ? (
                    <div>
                        <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">Content</label>
                        <textarea
                            value={content}
                            onChange={e => setContent(e.target.value)}
                            rows={4}
                            className="w-full bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded-lg px-4 py-3 text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-indigo-500 font-mono text-sm"
                            placeholder="Enter the secret content here..."
                            disabled={creating}
                        />
                    </div>
                ) : (
                    <div>
                        <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">Select Files</label>
                        <div
                            className={`border-2 border-dashed rounded-lg p-6 text-center transition-colors ${isDragging
                                ? 'border-indigo-500 bg-indigo-50 dark:bg-indigo-950/30'
                                : 'border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-900/50 hover:bg-slate-100 dark:hover:bg-slate-900'
                                }`}
                            onDragOver={handleDragOver}
                            onDragEnter={handleDragEnter}
                            onDragLeave={handleDragLeave}
                            onDrop={handleDrop}
                        >
                            {/* File list */}
                            {selectedFiles.length > 0 && (
                                <div className="mb-4 space-y-2">
                                    {selectedFiles.map((file, idx) => (
                                        <div key={idx} className="flex items-center gap-3 bg-white dark:bg-slate-750 rounded-lg px-3 py-2 border border-slate-200 dark:border-slate-600">
                                            <FileText className="w-5 h-5 text-indigo-500 flex-shrink-0" />
                                            <div className="flex-1 text-left min-w-0">
                                                <div className="font-medium text-sm text-slate-900 dark:text-white truncate">{file.name}</div>
                                                <div className="text-xs text-slate-500">{formatSize(file.size)}</div>
                                            </div>
                                            <button
                                                type="button"
                                                onClick={() => removeFile(idx)}
                                                className="text-slate-400 hover:text-red-500 transition-colors flex-shrink-0"
                                            >
                                                <Trash2 className="w-4 h-4" />
                                            </button>
                                        </div>
                                    ))}
                                    <div className="text-xs text-slate-400 text-right">
                                        {selectedFiles.length} file{selectedFiles.length > 1 ? 's' : ''} · {formatSize(selectedFiles.reduce((s, f) => s + f.size, 0))} total
                                    </div>
                                </div>
                            )}

                            {/* Upload prompt */}
                            <Upload className={`w-8 h-8 mx-auto mb-2 ${isDragging ? 'text-indigo-500' : 'text-slate-300'}`} />
                            <div className="text-sm text-slate-500">
                                {isDragging ? (
                                    <p className="font-medium text-indigo-600 dark:text-indigo-400">Drop your files here</p>
                                ) : (
                                    <>
                                        <label className="relative cursor-pointer rounded-md font-medium text-indigo-600 hover:text-indigo-500 focus-within:outline-none">
                                            <span>{selectedFiles.length > 0 ? 'Add more files' : 'Upload files'}</span>
                                            <input type="file" multiple className="sr-only" onChange={handleFileInput} disabled={creating} />
                                        </label>
                                        <p className="pl-1">or drag and drop</p>
                                    </>
                                )}
                            </div>
                            <p className="text-xs text-slate-400 mt-1">Up to 50MB per file (Chunked Upload)</p>
                        </div>
                    </div>
                )}

                {authType === 'trustkeys' && (
                    <div className="flex items-center gap-2 py-2">
                        <button
                            type="button"
                            onClick={() => setIsSigned(!isSigned)}
                            className={`flex items-center gap-2 px-3 py-2 rounded-lg border text-sm font-medium transition-colors ${isSigned
                                ? 'bg-indigo-50 dark:bg-indigo-900/20 border-indigo-200 dark:border-indigo-800 text-indigo-600 dark:text-indigo-400'
                                : 'bg-transparent border-slate-200 dark:border-slate-700 text-slate-500 hover:text-slate-700 dark:hover:text-slate-300'
                                }`}
                        >
                            <Shield className={`w-4 h-4 ${isSigned ? 'fill-current' : ''}`} />
                            {isSigned ? 'Digitally Sign Document' : 'Add Digital Signature'}
                            {isSigned && <Check className="w-3 h-3 ml-1" />}
                        </button>
                        <span className="text-xs text-slate-400">
                            (Requires PQC Identity)
                        </span>
                    </div>
                )}

                <div className="flex gap-3 justify-end mt-4">
                    <button
                        type="button"
                        onClick={onCancel}
                        disabled={creating}
                        className="px-4 py-2 text-slate-500 hover:text-slate-700 dark:hover:text-slate-300 text-sm font-medium transition-colors"
                    >
                        Cancel
                    </button>
                    <button
                        type="submit"
                        disabled={creating}
                        className="bg-indigo-600 hover:bg-indigo-500 text-white px-6 py-2 rounded-lg font-medium shadow-lg shadow-indigo-500/20 disabled:opacity-50 disabled:scale-95 transition-all flex items-center gap-2"
                    >
                        {creating ? <Loader2 className="w-5 h-5 animate-spin" /> : 'Create Secret'}
                    </button>
                </div>
            </form>
        </div>
    );
};

export default CreateSecret;
