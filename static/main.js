(function() {
    const dropZone = document.getElementById('dropZone');
    const fileInput = document.getElementById('fileInput');
    const selectBtn = document.getElementById('selectFilesBtn');
    const fileListContainer = document.getElementById('fileList');
    const fileCountSpan = document.getElementById('fileCount');
    const uploadProgress = document.getElementById('uploadProgress');
    const progressFill = document.getElementById('progressFill');
    const progressText = document.getElementById('progressText');
    const clearAllBtn = document.getElementById('clearAllBtn');

    // API Base URL
    const API_BASE = window.location.origin;

    function formatFileSize(bytes) {
        if (bytes === 0) return '0 B';
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
    }

    function getFileIconClass(fileName) {
        const ext = fileName.split('.').pop().toLowerCase();
        if (['jpg', 'jpeg', 'png', 'gif', 'svg', 'webp'].includes(ext)) return 'fa-file-image';
        if (['pdf'].includes(ext)) return 'fa-file-pdf';
        if (['doc', 'docx', 'txt', 'rtf', 'odt'].includes(ext)) return 'fa-file-lines';
        if (['xls', 'xlsx', 'csv'].includes(ext)) return 'fa-file-excel';
        if (['ppt', 'pptx'].includes(ext)) return 'fa-file-powerpoint';
        if (['zip', 'rar', '7z', 'tar', 'gz'].includes(ext)) return 'fa-file-zipper';
        if (['mp3', 'wav', 'ogg', 'flac'].includes(ext)) return 'fa-file-audio';
        if (['mp4', 'avi', 'mov', 'mkv'].includes(ext)) return 'fa-file-video';
        if (['js', 'html', 'css', 'py', 'java', 'cpp', 'json'].includes(ext)) return 'fa-file-code';
        return 'fa-file';
    }

    function createFileItem(fileData) {
        const fileName = fileData.original_name || fileData.name;
        const fileSize = fileData.size;
        const fileId = fileData.id;
        const storedName = fileData.stored_name;
        const fileDate = fileData.date || new Date(fileData.uploaded_at * 1000).toLocaleString();

        const sizeFormatted = formatFileSize(fileSize);
        const iconClass = getFileIconClass(fileName);

        const itemDiv = document.createElement('div');
        itemDiv.className = 'file-item';
        itemDiv.dataset.id = fileId;

        const iconSpan = document.createElement('span');
        iconSpan.className = 'file-icon';
        iconSpan.innerHTML = `<i class="fas ${iconClass}"></i>`;
        itemDiv.appendChild(iconSpan);

        const infoDiv = document.createElement('div');
        infoDiv.className = 'file-info';
        infoDiv.innerHTML = `
            <div class="file-name">${fileName}</div>
            <div class="file-meta">
                <i class="fas fa-circle"></i> ${sizeFormatted}
                <i class="fas fa-circle" style="opacity: 0.3;"></i> ${fileDate}
            </div>
        `;
        itemDiv.appendChild(infoDiv);

        const actionsDiv = document.createElement('div');
        actionsDiv.className = 'file-actions';

        const shareBtn = document.createElement('button');
        shareBtn.className = 'icon-btn';
        shareBtn.title = 'Share file';
        shareBtn.innerHTML = '<i class="fas fa-share-alt"></i>';
        shareBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            shareFile(fileId, fileName);
        });

        const downloadBtn = document.createElement('button');
        downloadBtn.className = 'icon-btn';
        downloadBtn.title = 'Download';
        downloadBtn.innerHTML = '<i class="fas fa-download"></i>';
        downloadBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            downloadFile(storedName, fileName);
        });

        const deleteBtn = document.createElement('button');
        deleteBtn.className = 'icon-btn';
        deleteBtn.title = 'Delete';
        deleteBtn.innerHTML = '<i class="fas fa-trash"></i>';
        deleteBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            deleteFile(fileId, itemDiv);
        });

        actionsDiv.appendChild(shareBtn);
        actionsDiv.appendChild(downloadBtn);
        actionsDiv.appendChild(deleteBtn);
        itemDiv.appendChild(actionsDiv);

        return itemDiv;
    }

    async function loadFiles() {
        try {
            const response = await fetch(`${API_BASE}/api/files`);
            const files = await response.json();
            
            fileListContainer.innerHTML = '';
            
            if (files.length === 0) {
                showEmptyPlaceholder();
            } else {
                files.forEach(file => {
                    const fileItem = createFileItem(file);
                    fileListContainer.appendChild(fileItem);
                });
            }
            
            updateFileCount();
        } catch (error) {
            console.error('Error loading files:', error);
            showError('Failed to load files');
        }
    }

    async function uploadFiles(files) {
        if (!files || files.length === 0) return;

        const formData = new FormData();
        for (let i = 0; i < files.length; i++) {
            formData.append('files', files[i]);
        }

        // Show progress bar
        uploadProgress.style.display = 'block';
        progressFill.style.width = '0%';
        progressText.textContent = 'Uploading...';

        try {
            const response = await fetch(`${API_BASE}/api/upload`, {
                method: 'POST',
                body: formData
            });

            const result = await response.json();

            if (response.ok && result.success) {
                progressFill.style.width = '100%';
                progressText.textContent = 'Upload complete!';
                
                // Reload files
                await loadFiles();
                
                setTimeout(() => {
                    uploadProgress.style.display = 'none';
                }, 2000);
            } else {
                throw new Error(result.error || 'Upload failed');
            }
        } catch (error) {
            console.error('Upload error:', error);
            progressText.textContent = 'Upload failed';
            progressFill.style.width = '0%';
            showError('Failed to upload files');
            
            setTimeout(() => {
                uploadProgress.style.display = 'none';
            }, 3000);
        }
    }

    async function shareFile(fileId, fileName) {
        try {
            const response = await fetch(`${API_BASE}/api/share/${fileId}`, {
                method: 'POST'
            });
            
            const result = await response.json();
            
            if (result.success) {
                // Copy to clipboard
                await navigator.clipboard.writeText(result.share_link);
                alert(`[+] Share link for "${fileName}" copied to clipboard!`);
            } else {
                throw new Error(result.error);
            }
        } catch (error) {
            console.error('Share error:', error);
            alert('[X] Failed to generate share link');
        }
    }

    function downloadFile(storedName, fileName) {
        window.location.href = `${API_BASE}/api/download/${storedName}`;
    }

    async function deleteFile(fileId, fileElement) {
        if (!confirm('Are you sure you want to delete this file?')) return;

        try {
            const response = await fetch(`${API_BASE}/api/delete/${fileId}`, {
                method: 'DELETE'
            });

            const result = await response.json();

            if (result.success) {
                fileElement.remove();
                updateFileCount();
                
                if (fileListContainer.children.length === 0) {
                    showEmptyPlaceholder();
                }
            } else {
                throw new Error(result.error);
            }
        } catch (error) {
            console.error('Delete error:', error);
            alert('[X] Failed to delete file');
        }
    }

    async function clearAllFiles() {
        if (!confirm('! Are you sure you want to delete ALL files?')) return;

        try {
            const response = await fetch(`${API_BASE}/api/clear`, {
                method: 'POST'
            });

            const result = await response.json();

            if (result.success) {
                await loadFiles();
                alert('[+] All files cleared');
            } else {
                throw new Error(result.error);
            }
        } catch (error) {
            console.error('Clear error:', error);
            alert('[X] Failed to clear files');
        }
    }

    function showEmptyPlaceholder() {
        const emptyDiv = document.createElement('div');
        emptyDiv.id = 'emptyPlaceholder';
        emptyDiv.className = 'empty-files';
        emptyDiv.innerHTML = `
            <i class="fas fa-share-from-square"></i>
            <p>No shared files yet — upload something!</p>
        `;
        fileListContainer.appendChild(emptyDiv);
    }

    function updateFileCount() {
        const items = fileListContainer.querySelectorAll('.file-item');
        const count = items.length;
        fileCountSpan.textContent = count + (count === 1 ? ' item' : ' items');
    }

    function showError(message) {
        // Simple error notification
        const errorDiv = document.createElement('div');
        errorDiv.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            background: #ff4444;
            color: white;
            padding: 1rem;
            border-radius: 8px;
            z-index: 1000;
        `;
        errorDiv.textContent = message;
        document.body.appendChild(errorDiv);
        
        setTimeout(() => {
            errorDiv.remove();
        }, 3000);
    }

    // Event Listeners
    dropZone.addEventListener('click', () => {
        fileInput.click();
    });

    ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
        dropZone.addEventListener(eventName, (e) => {
            e.preventDefault();
            e.stopPropagation();
        });
    });

    dropZone.addEventListener('dragover', () => {
        dropZone.classList.add('dragover');
    });

    dropZone.addEventListener('dragleave', () => {
        dropZone.classList.remove('dragover');
    });

    dropZone.addEventListener('drop', (e) => {
        dropZone.classList.remove('dragover');
        const files = e.dataTransfer.files;
        uploadFiles(files);
    });

    fileInput.addEventListener('change', (e) => {
        uploadFiles(e.target.files);
        fileInput.value = '';
    });

    selectBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        fileInput.click();
    });

    if (clearAllBtn) {
        clearAllBtn.addEventListener('click', clearAllFiles);
    }

    // Add progress bar styles
    const style = document.createElement('style');
    style.textContent = `
        .upload-progress {
            margin-top: 1rem;
            padding: 1rem;
            background: #f0f7ff;
            border-radius: 1rem;
        }
        .progress-bar {
            width: 100%;
            height: 8px;
            background: #d4e2fc;
            border-radius: 4px;
            overflow: hidden;
            margin-bottom: 0.5rem;
        }
        .progress-fill {
            height: 100%;
            background: #1e4f8a;
            transition: width 0.3s ease;
            width: 0%;
        }
        #progressText {
            font-size: 0.9rem;
            color: #1e4f8a;
        }
        .clear-btn:hover {
            background: #f0f7ff !important;
            border-color: #ff4444 !important;
            color: #ff4444 !important;
        }
    `;
    document.head.appendChild(style);

    // Initialize
    loadFiles();
})();