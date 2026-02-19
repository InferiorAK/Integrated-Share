(function() {
    const dropZone = document.getElementById('dropZone');
    const fileInput = document.getElementById('fileInput');
    const selectBtn = document.getElementById('selectFilesBtn');
    const fileListContainer = document.getElementById('fileList');
    const fileCountSpan = document.getElementById('fileCount');

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
        let fileName, fileSize, fileDate;
        if (fileData instanceof File) {
            fileName = fileData.name;
            fileSize = fileData.size;
            fileDate = 'just now';
        } else {
            fileName = fileData.name;
            fileSize = fileData.size;
            fileDate = fileData.date || 'shared 1 hour ago';
        }

        const sizeFormatted = formatFileSize(fileSize);
        const iconClass = getFileIconClass(fileName);

        const itemDiv = document.createElement('div');
        itemDiv.className = 'file-item';

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

        const copyBtn = document.createElement('button');
        copyBtn.className = 'icon-btn';
        copyBtn.title = 'Copy mock link';
        copyBtn.innerHTML = '<i class="fas fa-link"></i>';
        copyBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            alert(`🔗 Mock: link for "${fileName}" copied (demo)`);
        });

        const downloadBtn = document.createElement('button');
        downloadBtn.className = 'icon-btn';
        downloadBtn.title = 'Download (mock)';
        downloadBtn.innerHTML = '<i class="fas fa-download"></i>';
        downloadBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            alert(`⬇️ Mock download: "${fileName}" (no actual file)`);
        });

        actionsDiv.appendChild(copyBtn);
        actionsDiv.appendChild(downloadBtn);
        itemDiv.appendChild(actionsDiv);

        return itemDiv;
    }

    function addFilesToUI(files, prepend = true) {
        if (!files || files.length === 0) return;

        const emptyPlaceholder = document.getElementById('emptyPlaceholder');
        if (emptyPlaceholder) emptyPlaceholder.remove();

        const fragment = document.createDocumentFragment();
        for (let i = 0; i < files.length; i++) {
            const fileItem = createFileItem(files[i]);
            fragment.appendChild(fileItem);
        }

        if (prepend) {
            fileListContainer.prepend(fragment);
        } else {
            fileListContainer.appendChild(fragment);
        }

        updateFileCount();
    }

    function updateFileCount() {
        const items = fileListContainer.querySelectorAll('.file-item:not(#emptyPlaceholder)');
        const count = items.length;
        fileCountSpan.textContent = count + (count === 1 ? ' item' : ' items');
    }

    function handleFiles(fileList) {
        if (!fileList || fileList.length === 0) return;
        const filesArray = Array.from(fileList);
        addFilesToUI(filesArray, true);
    }

    const mockFiles = [
        { name: 'vacation_planning.pdf', size: 2.4 * 1024 * 1024, date: 'shared 2 hours ago' },
        { name: 'team_photo_2025.jpg', size: 5.1 * 1024 * 1024, date: 'shared yesterday' },
        { name: 'presentation_deck.pptx', size: 3.8 * 1024 * 1024, date: 'shared 3 days ago' },
        { name: 'notes_onboarding.txt', size: 128 * 1024, date: 'shared last week' }
    ];

    function loadMockFiles() {
        if (fileListContainer.children.length === 0) {
            mockFiles.forEach(mock => addFilesToUI([mock], false));
        }
        updateFileCount();
    }

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
        handleFiles(files);
    });

    fileInput.addEventListener('change', (e) => {
        handleFiles(e.target.files);
        fileInput.value = '';
    });

    selectBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        fileInput.click();
    });

    function initPlaceholder() {
        if (fileListContainer.children.length === 0) {
            const emptyDiv = document.createElement('div');
            emptyDiv.id = 'emptyPlaceholder';
            emptyDiv.className = 'empty-files';
            emptyDiv.innerHTML = `
                <i class="fas fa-share-from-square"></i>
                <p>No shared files yet — upload something!</p>
            `;
            fileListContainer.appendChild(emptyDiv);
        }
    }

    initPlaceholder();
    loadMockFiles();

    window.addEventListener('load', function() {
        if (fileListContainer.querySelectorAll('.file-item').length > 0) {
            const placeholder = document.getElementById('emptyPlaceholder');
            if (placeholder) placeholder.remove();
            updateFileCount();
        } else {
            fileCountSpan.textContent = '0 items';
        }
    });

    const originalHandleFiles = handleFiles;
    handleFiles = function(files) {
        const placeholder = document.getElementById('emptyPlaceholder');
        if (placeholder) placeholder.remove();
        originalHandleFiles(files);
    };
    const boundHandleFiles = handleFiles.bind(this);
    dropZone.addEventListener('drop', (e) => {
        dropZone.classList.remove('dragover');
        const files = e.dataTransfer.files;
        boundHandleFiles(files);
    });

    fileInput.addEventListener('change', (e) => {
        boundHandleFiles(e.target.files);
        fileInput.value = '';
    });

    window.boundHandleFiles = boundHandleFiles;

    const originalAddFilesToUI = addFilesToUI;
    window.addFilesToUI = function(files, prepend) {
        originalAddFilesToUI(files, prepend);
        updateFileCount();
    };

    updateFileCount();
})();
