(function () {
    const fileListContainer = document.getElementById('fileList');
    const fileCountSpan = document.getElementById('fileCount');
    const uploadProgress = document.getElementById('uploadProgress');
    const progressFill = document.getElementById('progressFill');
    const progressText = document.getElementById('progressText');
    const clearAllBtn = document.getElementById('clearAllBtn');
    const emptyTrashBtn = document.getElementById('emptyTrashBtn');
    const newFolderBtn = document.getElementById('newFolderBtn');
    const folderBackBtn = document.getElementById('folderBackBtn');
    const fileInput = document.getElementById('fileInput');
    const dropZone = document.getElementById('dropZone');
    const dragOverlay = document.getElementById('dragOverlay');
    const searchInput = document.getElementById('searchInput');

    const folderModal = document.getElementById('folderModal');
    const folderNameInput = document.getElementById('folderNameInput');
    const folderFeedback = document.getElementById('folderFeedback');
    const createFolderConfirmBtn = document.getElementById('createFolderConfirmBtn');
    const folderModalCancelBtn = document.getElementById('folderModalCancelBtn');
    const renameModal = document.getElementById('renameModal');
    const renameModalTitle = document.getElementById('renameModalTitle');
    const renameNameInput = document.getElementById('renameNameInput');
    const renameFeedback = document.getElementById('renameFeedback');
    const renameConfirmBtn = document.getElementById('renameConfirmBtn');
    const renameCancelBtn = document.getElementById('renameCancelBtn');
    const infoModal = document.getElementById('infoModal');
    const infoModalTitle = document.getElementById('infoModalTitle');
    const infoMetaRows = document.getElementById('infoMetaRows');
    const infoSharesWrap = document.getElementById('infoSharesWrap');
    const infoSharesList = document.getElementById('infoSharesList');
    const infoCloseBtn = document.getElementById('infoCloseBtn');
    const confirmModal = document.getElementById('confirmModal');
    const confirmTitle = document.getElementById('confirmTitle');
    const confirmMessage = document.getElementById('confirmMessage');
    const confirmCancelBtn = document.getElementById('confirmCancelBtn');
    const confirmOkBtn = document.getElementById('confirmOkBtn');

    const API = window.location.origin;
    let allFiles = [];
    let allFolders = [];
    let sharedFolders = [];
    let trashFiles = [];
    let currentFilter = 'mine';
    let searchQuery = '';
    let shareTargetId = null;
    let shareTargetType = 'file';
    let currentFolderId = null;
    let renameTargetId = null;
    let renameTargetType = null;

    async function apiFetch(url, options = {}) {
        const res = await fetch(url, options);
        if (res.status === 401) {
            window.location.href = '/login';
            return null;
        }
        return res;
    }

    window.doLogout = async function () {
        try { await fetch(`${API}/api/auth/logout`, { method: 'POST' }); } catch {}
        window.location.href = '/login';
    };

    async function loadUserInfo() {
        try {
            const res = await apiFetch(`${API}/api/auth/me`);
            if (!res) return;
            const user = await res.json();

            const avatar = document.getElementById('userAvatar');
            const avatarImg = document.getElementById('userAvatarImg');
            const avatarInitial = document.getElementById('userAvatarInitial');
            const initial = (user.username || '?')[0].toUpperCase();

            if (avatarInitial) avatarInitial.textContent = initial;

            if (avatarImg && avatarInitial && user.profile_image_url) {
                avatarImg.src = user.profile_image_url;
                avatarImg.style.display = 'block';
                avatarInitial.style.display = 'none';
            } else if (avatarImg && avatarInitial) {
                avatarImg.style.display = 'none';
                avatarInitial.style.display = 'flex';
            }

            const pct = user.storage_limit > 0
                ? Math.min(100, Math.round((user.storage_used / user.storage_limit) * 100)) : 0;
            const usedStr = formatSize(user.storage_used);
            const limitStr = formatSize(user.storage_limit);

            const topFill = document.getElementById('storageFill');
            const topText = document.getElementById('storageText');
            const sideFill = document.getElementById('sideStorageFill');
            const sideText = document.getElementById('sideStorageText');

            if (topFill) topFill.style.width = pct + '%';
            if (topText) topText.textContent = usedStr + ' / ' + limitStr;
            if (sideFill) sideFill.style.width = pct + '%';
            if (sideText) sideText.textContent = usedStr + ' of ' + limitStr;

            const adminBtn = document.getElementById('adminLink');
            if (adminBtn && user.is_admin) adminBtn.style.display = 'flex';
        } catch {}
    }

    async function loadFolders() {
        try {
            const res = await apiFetch(`${API}/api/folders`);
            if (!res) return;
            allFolders = await res.json();
        } catch {
            allFolders = [];
        }
    }

    async function loadSharedFolders() {
        try {
            const res = await apiFetch(`${API}/api/folders/shared`);
            if (!res) return;
            sharedFolders = await res.json();
        } catch {
            sharedFolders = [];
        }
    }

    async function loadFiles() {
        try {
            const [filesRes, trashRes] = await Promise.all([
                apiFetch(`${API}/api/files`),
                apiFetch(`${API}/api/trash`),
            ]);
            if (!filesRes || !trashRes) return;
            allFiles = await filesRes.json();
            trashFiles = await trashRes.json();
            await Promise.all([loadFolders(), loadSharedFolders()]);
            renderFiles();
        } catch {
            showToast('Failed to load files', 'error');
        }
    }

    function setToolbarState() {
        const inMine = currentFilter === 'mine';
        const inTrash = currentFilter === 'trash';
        const inFolder = (currentFilter === 'mine' || currentFilter === 'shared') && !!currentFolderId;

        if (clearAllBtn) clearAllBtn.style.display = inMine && !inFolder ? 'flex' : 'none';
        if (newFolderBtn) newFolderBtn.style.display = inMine && !inFolder ? 'flex' : 'none';
        if (emptyTrashBtn) emptyTrashBtn.style.display = inTrash ? 'flex' : 'none';
        if (folderBackBtn) folderBackBtn.style.display = inFolder ? 'inline-flex' : 'none';
    }

    function getCurrentFolder() {
        return allFolders.find(x => x.id === currentFolderId)
            || sharedFolders.find(x => x.id === currentFolderId)
            || null;
    }

    function renderFiles() {
        const title = document.getElementById('sectionTitle');
        const folder = getCurrentFolder();

        if (title) {
            if (currentFilter === 'shared') title.textContent = 'Shared with me';
            else if (currentFilter === 'trash') title.textContent = 'Trash';
            else if ((currentFilter === 'mine' || currentFilter === 'shared') && folder) {
                const base = currentFilter === 'mine' ? 'My Files' : 'Shared with me';
                title.textContent = `${base} / ${folder.name}`;
            }
            else title.textContent = 'My Files';
        }

        setToolbarState();
        fileListContainer.innerHTML = '';

        if (currentFilter === 'mine' && !currentFolderId) {
            renderRootMineView();
            return;
        }
        if (currentFilter === 'shared' && !currentFolderId) {
            renderRootSharedView();
            return;
        }

        let files = [];
        if (currentFilter === 'shared') {
            files = allFiles.filter(f => f.folder_id === currentFolderId && !f.is_owned);
        } else if (currentFilter === 'trash') {
            files = trashFiles.slice();
        } else {
            files = allFiles.filter(f => f.owner === '' && f.folder_id === currentFolderId);
        }

        files = files.filter(f => !searchQuery || (f.original_name || '').toLowerCase().includes(searchQuery));

        if (!files.length) {
            showEmpty();
        } else {
            if (dropZone) dropZone.style.display = 'none';
            files.forEach(f => {
                if (currentFilter === 'trash') {
                    fileListContainer.appendChild(f.type === 'folder' ? makeTrashFolderCard(f) : makeTrashCard(f));
                } else {
                    fileListContainer.appendChild(makeFileCard(f));
                }
            });
        }
        updateCount(files.length);
    }

    function renderRootMineView() {
        const folderCards = allFolders.filter(f => !searchQuery || f.name.toLowerCase().includes(searchQuery));
        const rootFiles = allFiles.filter(f => f.owner === '' && !f.folder_id)
            .filter(f => !searchQuery || (f.original_name || '').toLowerCase().includes(searchQuery));

        const total = folderCards.length + rootFiles.length;
        if (!total) {
            showEmpty();
            updateCount(0);
            return;
        }

        if (dropZone) dropZone.style.display = 'none';
        folderCards.forEach(folder => fileListContainer.appendChild(makeFolderCard(folder)));
        rootFiles.forEach(f => fileListContainer.appendChild(makeFileCard(f)));
        updateCount(total);
    }

    function renderRootSharedView() {
        const folders = sharedFolders.filter(f => !searchQuery || f.name.toLowerCase().includes(searchQuery));
        const directFiles = allFiles
            .filter(f => !f.is_owned && !f.shared_via_folder)
            .filter(f => !searchQuery || (f.original_name || '').toLowerCase().includes(searchQuery));

        const total = folders.length + directFiles.length;
        if (!total) {
            showEmpty();
            updateCount(0);
            return;
        }

        if (dropZone) dropZone.style.display = 'none';
        folders.forEach(folder => fileListContainer.appendChild(makeFolderCard(folder)));
        directFiles.forEach(f => fileListContainer.appendChild(makeFileCard(f)));
        updateCount(total);
    }

    function makeFolderCard(folder) {
        const ownFolder = !!folder.is_owned || !folder.owner;
        const card = document.createElement('div');
        card.className = 'file-card folder-card';
        card.innerHTML = `
            <div class="file-card-header">
                <i class="fas fa-folder"></i>
            </div>
            <div class="file-card-actions">
                <button class="card-menu-trigger" title="More actions"><i class="fas fa-ellipsis-v"></i></button>
                <div class="card-menu">
                    <button class="card-menu-item btn-open"><i class="fas fa-folder-open"></i> Open</button>
                    <button class="card-menu-item btn-info"><i class="fas fa-circle-info"></i> Info</button>
                    ${ownFolder ? '<button class="card-menu-item btn-rename-folder"><i class="fas fa-pen"></i> Rename</button>' : ''}
                    ${ownFolder ? '<button class="card-menu-item btn-share-folder"><i class="fas fa-share-alt"></i> Share folder</button>' : ''}
                    ${ownFolder ? '<button class="card-menu-item btn-del"><i class="fas fa-trash"></i> Delete folder</button>' : ''}
                </div>
            </div>
            <div class="file-card-body">
                <div class="file-card-name" title="${folder.name}">${folder.name}</div>
                <div class="file-card-meta">${folder.file_count} file(s)${ownFolder ? '' : ` &middot; from ${folder.owner || '—'}`}</div>
            </div>`;
        const openBtn = card.querySelector('.btn-open');
        if (openBtn) {
            openBtn.onclick = e => {
                e.stopPropagation();
                openFolder(folder.id);
            };
        }
        const delBtn = card.querySelector('.btn-del');
        if (delBtn) {
            delBtn.onclick = async e => {
                e.stopPropagation();
                await deleteFolder(folder.id, folder.name);
            };
        }
        const renameBtn = card.querySelector('.btn-rename-folder');
        if (renameBtn) {
            renameBtn.onclick = e => {
                e.stopPropagation();
                openRenameModal('folder', folder.id, folder.name);
            };
        }
        const shareFolderBtn = card.querySelector('.btn-share-folder');
        if (shareFolderBtn) {
            shareFolderBtn.onclick = async e => {
                e.stopPropagation();
                openShareModal(folder.id, folder.name, 'folder');
            };
        }
        const infoBtn = card.querySelector('.btn-info');
        if (infoBtn) {
            infoBtn.onclick = async e => {
                e.stopPropagation();
                await openInfoModal('folder', folder.id);
            };
        }
        bindCardMenu(card);
        card.onclick = () => openFolder(folder.id);
        return card;
    }

    async function openFolder(folderId) {
        currentFolderId = folderId;
        if (currentFilter === 'mine') {
            try {
                await apiFetch(`${API}/api/folders/${folderId}/open`, { method: 'POST' });
            } catch {}
        }
        renderFiles();
    }

    function makeFileCard(f) {
        const name = f.original_name || 'Unknown';
        const ext = name.split('.').pop().toLowerCase();
        const typeClass = cardTypeClass(ext);
        const ownFile = !!f.is_owned || !f.owner;

        const card = document.createElement('div');
        card.className = `file-card ${typeClass}`;
        card.dataset.id = f.id;
        card.innerHTML = `
            <div class="file-card-header">
                <i class="fas ${fileIcon(name)}"></i>
            </div>
            <div class="file-card-actions">
                <button class="card-menu-trigger" title="More actions"><i class="fas fa-ellipsis-v"></i></button>
                <div class="card-menu">
                    <button class="card-menu-item btn-view"><i class="fas fa-eye"></i> View</button>
                    <button class="card-menu-item btn-dl"><i class="fas fa-download"></i> Download</button>
                    <button class="card-menu-item btn-info"><i class="fas fa-circle-info"></i> Info</button>
                    ${ownFile ? '<button class="card-menu-item btn-rename"><i class="fas fa-pen"></i> Rename</button>' : ''}
                    ${ownFile ? '<button class="card-menu-item btn-share"><i class="fas fa-share-alt"></i> Share</button>' : ''}
                    ${ownFile ? '<button class="card-menu-item btn-del"><i class="fas fa-trash"></i> Move to trash</button>' : ''}
                </div>
            </div>
            <div class="file-card-body">
                <div class="file-card-name" title="${name}">${name}</div>
                <div class="file-card-meta">${formatSize(f.size)} &middot; ${f.date || ''}</div>
                ${f.owner ? `<div class="file-card-owner"><i class="fas fa-user"></i> ${f.owner}</div>` : ''}
            </div>`;

        const dlBtn = card.querySelector('.btn-dl');
        if (dlBtn) dlBtn.onclick = e => { e.stopPropagation(); window.location.href = `${API}/api/download/${f.stored_name}`; };
        const viewBtn = card.querySelector('.btn-view');
        if (viewBtn) viewBtn.onclick = e => { e.stopPropagation(); window.open(`${API}/api/view/${f.stored_name}`, '_blank', 'noopener'); };

        const shareBtn = card.querySelector('.btn-share');
        if (shareBtn) shareBtn.onclick = e => { e.stopPropagation(); openShareModal(f.id, name, 'file'); };

        const infoBtn = card.querySelector('.btn-info');
        if (infoBtn) infoBtn.onclick = async e => { e.stopPropagation(); await openInfoModal('file', f.id); };

        const renameBtn = card.querySelector('.btn-rename');
        if (renameBtn) renameBtn.onclick = e => { e.stopPropagation(); openRenameModal('file', f.id, name); };

        const delBtn = card.querySelector('.btn-del');
        if (delBtn) delBtn.onclick = e => { e.stopPropagation(); deleteFile(f.id, card); };

        bindCardMenu(card);
        card.onclick = () => window.location.href = `${API}/api/view/${f.stored_name}`;
        return card;
    }

    function bindCardMenu(card) {
        const actions = card.querySelector('.file-card-actions');
        const trigger = card.querySelector('.card-menu-trigger');
        if (!actions || !trigger) return;
        trigger.onclick = e => {
            e.stopPropagation();
            const isOpen = actions.classList.contains('open');
            closeCardMenus();
            if (!isOpen) actions.classList.add('open');
        };
    }

    function closeCardMenus() {
        document.querySelectorAll('.file-card-actions.open').forEach(el => el.classList.remove('open'));
    }

    function makeTrashCard(f) {
        const card = document.createElement('div');
        card.className = 'file-card type-doc';
        card.innerHTML = `
            <div class="file-card-header">
                <i class="fas fa-trash-can"></i>
            </div>
            <div class="file-card-actions" style="display:flex;gap:0.15rem;background:rgba(255,255,255,0.92);border-radius:0.5rem;padding:0.2rem;">
                <button class="card-btn" title="Restore"><i class="fas fa-rotate-left"></i></button>
                <button class="card-btn btn-del" title="Delete permanently"><i class="fas fa-skull-crossbones"></i></button>
            </div>
            <div class="file-card-body">
                <div class="file-card-name" title="${f.original_name}">${f.original_name}</div>
                <div class="file-card-meta">${formatSize(f.size)} &middot; deleted ${f.date || ''}</div>
            </div>`;

        card.querySelector('.card-btn').onclick = async e => {
            e.stopPropagation();
            await restoreFile(f.id);
        };
        card.querySelector('.btn-del').onclick = async e => {
            e.stopPropagation();
            await deleteTrashFile(f.id);
        };
        return card;
    }

    function makeTrashFolderCard(folder) {
        const card = document.createElement('div');
        card.className = 'file-card folder-card';
        card.innerHTML = `
            <div class="file-card-header">
                <i class="fas fa-folder-minus"></i>
            </div>
            <div class="file-card-actions" style="display:flex;gap:0.15rem;background:rgba(255,255,255,0.92);border-radius:0.5rem;padding:0.2rem;">
                <button class="card-btn" title="Restore folder"><i class="fas fa-rotate-left"></i></button>
                <button class="card-btn btn-del" title="Delete folder permanently"><i class="fas fa-skull-crossbones"></i></button>
            </div>
            <div class="file-card-body">
                <div class="file-card-name" title="${folder.name}">${folder.name}</div>
                <div class="file-card-meta">${folder.file_count || 0} file(s) &middot; deleted ${folder.date || ''}</div>
            </div>`;

        card.querySelector('.card-btn').onclick = async e => {
            e.stopPropagation();
            await restoreTrashFolder(folder.id);
        };
        card.querySelector('.btn-del').onclick = async e => {
            e.stopPropagation();
            await deleteTrashFolder(folder.id);
        };
        return card;
    }

    async function uploadFiles(files) {
        if (!files || !files.length) return;
        const fd = new FormData();
        Array.from(files).forEach(f => fd.append('files', f));
        if (currentFilter === 'mine' && currentFolderId) fd.append('folder_id', currentFolderId);

        uploadProgress.style.display = 'block';
        progressFill.style.width = '10%';
        progressText.textContent = `Uploading ${files.length} file(s)…`;

        try {
            const res = await apiFetch(`${API}/api/upload`, { method: 'POST', body: fd });
            if (!res) return;
            const data = await res.json();

            if (res.ok && data.success) {
                progressFill.style.width = '100%';
                progressText.textContent = `Done — ${data.files.length} file(s) uploaded.`;
                await loadFiles();
                await loadUserInfo();
                if (data.warning) showToast(data.warning, 'warning');
                setTimeout(() => {
                    uploadProgress.style.display = 'none';
                    progressFill.style.width = '0%';
                }, 2500);
            } else {
                throw new Error(data.error || 'Upload failed');
            }
        } catch (err) {
            progressText.textContent = 'Upload failed';
            progressFill.style.width = '0%';
            showToast(err.message || 'Upload failed', 'error');
            setTimeout(() => { uploadProgress.style.display = 'none'; }, 3500);
        }
    }

    function openFolderModal() {
        if (!folderModal) return;
        folderModal.classList.add('open');
        folderNameInput.value = '';
        folderFeedback.className = 'modal-feedback';
        folderFeedback.textContent = '';
        setTimeout(() => folderNameInput.focus(), 20);
    }

    function closeFolderModal() {
        if (!folderModal) return;
        folderModal.classList.remove('open');
    }

    function openRenameModal(type, id, currentName) {
        if (!renameModal) return;
        renameTargetType = type;
        renameTargetId = id;
        renameModalTitle.innerHTML = type === 'folder'
            ? '<i class="fas fa-folder"></i> Rename folder'
            : '<i class="fas fa-file"></i> Rename file';
        renameNameInput.value = currentName || '';
        renameFeedback.className = 'modal-feedback';
        renameFeedback.textContent = '';
        renameModal.classList.add('open');
        setTimeout(() => {
            renameNameInput.focus();
            renameNameInput.select();
        }, 20);
    }

    function closeRenameModal() {
        if (!renameModal) return;
        renameModal.classList.remove('open');
        renameTargetType = null;
        renameTargetId = null;
    }

    function confirmAction(message, options = {}) {
        const { title = 'Confirm action', confirmText = 'Confirm', danger = true } = options;
        if (!confirmModal) return Promise.resolve(false);

        return new Promise(resolve => {
            confirmTitle.innerHTML = `<i class="fas ${danger ? 'fa-triangle-exclamation' : 'fa-circle-check'}"></i> ${title}`;
            confirmMessage.textContent = message;
            confirmOkBtn.innerHTML = `${danger ? '<i class="fas fa-trash"></i>' : '<i class="fas fa-check"></i>'} ${confirmText}`;
            confirmOkBtn.className = danger ? 'btn-primary btn-dangerish' : 'btn-primary';
            confirmModal.classList.add('open');

            const cleanup = result => {
                confirmModal.classList.remove('open');
                confirmOkBtn.className = 'btn-primary';
                confirmOkBtn.innerHTML = '<i class="fas fa-trash"></i> Confirm';
                confirmOkBtn.onclick = null;
                confirmCancelBtn.onclick = null;
                confirmModal.onclick = null;
                resolve(result);
            };

            confirmOkBtn.onclick = () => cleanup(true);
            confirmCancelBtn.onclick = () => cleanup(false);
            confirmModal.onclick = e => {
                if (e.target === confirmModal) cleanup(false);
            };
        });
    }

    async function createFolder() {
        const name = (folderNameInput.value || '').trim();
        if (!name) {
            folderFeedback.textContent = 'Folder name is required';
            folderFeedback.className = 'modal-feedback error';
            return;
        }
        try {
            const res = await apiFetch(`${API}/api/folders`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ name }),
            });
            if (!res) return;
            const data = await res.json();
            if (data.success) {
                await loadFiles();
                closeFolderModal();
                showToast(`Folder "${name}" created`, 'success');
            } else {
                folderFeedback.textContent = data.error || 'Failed to create folder';
                folderFeedback.className = 'modal-feedback error';
            }
        } catch {
            folderFeedback.textContent = 'Failed to create folder';
            folderFeedback.className = 'modal-feedback error';
        }
    }

    async function doRename() {
        const newName = (renameNameInput.value || '').trim();
        if (!newName) {
            renameFeedback.textContent = 'Name is required';
            renameFeedback.className = 'modal-feedback error';
            return;
        }
        if (!renameTargetType || !renameTargetId) return;

        const endpoint = renameTargetType === 'folder'
            ? `${API}/api/folders/${renameTargetId}/rename`
            : `${API}/api/files/${renameTargetId}/rename`;
        try {
            const res = await apiFetch(endpoint, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ name: newName }),
            });
            if (!res) return;
            const data = await res.json();
            if (data.success) {
                closeRenameModal();
                await loadFiles();
                showToast(renameTargetType === 'folder' ? 'Folder renamed' : 'File renamed', 'success');
            } else {
                renameFeedback.textContent = data.error || 'Rename failed';
                renameFeedback.className = 'modal-feedback error';
            }
        } catch {
            renameFeedback.textContent = 'Rename failed';
            renameFeedback.className = 'modal-feedback error';
        }
    }

    function closeInfoModal() {
        if (!infoModal) return;
        infoModal.classList.remove('open');
    }

    async function revokeShareAccess(kind, shareId) {
        const ok = await confirmAction('Remove this shared access?', { title: 'Remove access', confirmText: 'Remove' });
        if (!ok) return;
        try {
            const endpoint = kind === 'folder'
                ? `${API}/api/share/folder/revoke/${shareId}`
                : `${API}/api/share/file/revoke/${shareId}`;
            const res = await apiFetch(endpoint, { method: 'DELETE' });
            if (!res) return;
            const data = await res.json();
            if (!data.success) return showToast(data.error || 'Failed to remove access', 'error');
            showToast('Shared access removed', 'success');
            await loadFiles();
            if (infoModal.classList.contains('open')) {
                const type = infoModal.dataset.type;
                const id = infoModal.dataset.id;
                if (type && id) await openInfoModal(type, id);
            }
        } catch {
            showToast('Failed to remove access', 'error');
        }
    }

    async function openInfoModal(type, id) {
        if (!infoModal) return;
        const endpoint = type === 'folder' ? `${API}/api/folders/${id}/info` : `${API}/api/files/${id}/info`;
        try {
            const res = await apiFetch(endpoint);
            if (!res) return;
            const data = await res.json();
            if (!res.ok) {
                showToast(data.error || 'Failed to load info', 'error');
                return;
            }

            infoModal.dataset.type = type;
            infoModal.dataset.id = id;
            infoModalTitle.innerHTML = type === 'folder'
                ? '<i class="fas fa-folder-open"></i> Folder details'
                : '<i class="fas fa-file-lines"></i> File details';

            const rows = [];
            rows.push(['Name', data.name || '—']);
            rows.push(['Owner', data.owner || '—']);
            if (type === 'file') {
                rows.push(['Size', data.size_formatted || '—']);
                rows.push(['Uploaded', data.uploaded_at || '—']);
                rows.push(['Folder', data.folder_name || 'Root']);
            } else {
                rows.push(['Created', data.created_at || '—']);
                rows.push(['Files', String(data.file_count ?? 0)]);
                rows.push(['Total size', data.total_size_formatted || '0 B']);
            }

            infoMetaRows.innerHTML = rows.map(([k, v]) => `
                <div class="info-row">
                    <div class="info-key">${k}</div>
                    <div class="info-val" title="${v}">${v}</div>
                </div>
            `).join('');

            if (!data.can_manage_shares) {
                infoSharesWrap.style.display = 'none';
            } else {
                infoSharesWrap.style.display = '';
                const shares = data.shares || [];
                if (!shares.length) {
                    infoSharesList.innerHTML = '<div class="info-empty">No active shares</div>';
                } else {
                    infoSharesList.innerHTML = shares.map(s => `
                        <div class="info-share-item">
                            <div>
                                <div class="info-share-main">${s.scope === 'public' ? 'Public link' : (s.shared_with || '—')}</div>
                                <div class="info-share-sub">Created ${s.created_at || '—'} · Expires ${s.expires_at || '—'}</div>
                            </div>
                            <button class="del-btn info-revoke-btn" data-share-id="${s.share_id}" data-kind="${type}">
                                <i class="fas fa-user-slash"></i>
                            </button>
                        </div>
                    `).join('');
                    infoSharesList.querySelectorAll('.info-revoke-btn').forEach(btn => {
                        btn.addEventListener('click', async e => {
                            e.stopPropagation();
                            await revokeShareAccess(btn.dataset.kind, btn.dataset.shareId);
                        });
                    });
                }
            }
            infoModal.classList.add('open');
        } catch {
            showToast('Failed to load info', 'error');
        }
    }

    async function deleteFile(fileId, el) {
        if (!await confirmAction('Move this file to trash?', { title: 'Move to trash', confirmText: 'Move', danger: false })) return;
        try {
            const res = await apiFetch(`${API}/api/delete/${fileId}`, { method: 'DELETE' });
            if (!res) return;
            const data = await res.json();
            if (data.success) {
                el.remove();
                allFiles = allFiles.filter(f => f.id !== fileId);
                await loadFiles();
                await loadUserInfo();
                showToast('Moved to trash', 'success');
            } else {
                showToast(data.error || 'Delete failed', 'error');
            }
        } catch {
            showToast('Delete failed', 'error');
        }
    }

    async function deleteFolder(folderId, folderName) {
        if (!await confirmAction(`Delete folder "${folderName}"? Files inside will move to trash.`, { title: 'Delete folder', confirmText: 'Delete' })) return;
        try {
            const res = await apiFetch(`${API}/api/folders/${folderId}`, { method: 'DELETE' });
            if (!res) return;
            const data = await res.json();
            if (data.success) {
                if (currentFolderId === folderId) currentFolderId = null;
                await loadFiles();
                showToast('Folder moved to trash', 'success');
            } else {
                showToast(data.error || 'Failed to delete folder', 'error');
            }
        } catch {
            showToast('Failed to delete folder', 'error');
        }
    }

    async function clearAll() {
        if (!await confirmAction('Move all your files to trash?', { title: 'Clear My Files', confirmText: 'Move all', danger: false })) return;
        try {
            const res = await apiFetch(`${API}/api/clear`, { method: 'POST' });
            if (!res) return;
            const data = await res.json();
            if (data.success) {
                await loadFiles();
                await loadUserInfo();
                showToast('All files moved to trash', 'success');
            } else {
                showToast(data.error || 'Failed to clear', 'error');
            }
        } catch {
            showToast('Failed to clear files', 'error');
        }
    }

    async function restoreFile(fileId) {
        try {
            const res = await apiFetch(`${API}/api/trash/restore/${fileId}`, { method: 'POST' });
            if (!res) return;
            const data = await res.json();
            if (data.success) {
                showToast('File restored', 'success');
                await loadFiles();
                await loadUserInfo();
            } else {
                showToast(data.error || 'Restore failed', 'error');
            }
        } catch {
            showToast('Restore failed', 'error');
        }
    }

    async function deleteTrashFile(fileId) {
        if (!await confirmAction('Delete this file permanently? This cannot be undone.', { title: 'Permanent delete', confirmText: 'Delete permanently' })) return;
        try {
            const res = await apiFetch(`${API}/api/trash/delete/${fileId}`, { method: 'DELETE' });
            if (!res) return;
            const data = await res.json();
            if (data.success) {
                showToast('Permanently deleted', 'success');
                await loadFiles();
                await loadUserInfo();
            } else {
                showToast(data.error || 'Permanent delete failed', 'error');
            }
        } catch {
            showToast('Permanent delete failed', 'error');
        }
    }

    async function restoreTrashFolder(folderId) {
        try {
            const res = await apiFetch(`${API}/api/trash/folders/restore/${folderId}`, { method: 'POST' });
            if (!res) return;
            const data = await res.json();
            if (data.success) {
                showToast('Folder restored', 'success');
                await loadFiles();
                await loadUserInfo();
            } else {
                showToast(data.error || 'Folder restore failed', 'error');
            }
        } catch {
            showToast('Folder restore failed', 'error');
        }
    }

    async function deleteTrashFolder(folderId) {
        if (!await confirmAction('Delete this folder permanently? This cannot be undone.', { title: 'Permanent delete', confirmText: 'Delete permanently' })) return;
        try {
            const res = await apiFetch(`${API}/api/trash/folders/delete/${folderId}`, { method: 'DELETE' });
            if (!res) return;
            const data = await res.json();
            if (data.success) {
                showToast('Folder permanently deleted', 'success');
                await loadFiles();
                await loadUserInfo();
            } else {
                showToast(data.error || 'Folder delete failed', 'error');
            }
        } catch {
            showToast('Folder delete failed', 'error');
        }
    }

    async function emptyTrash() {
        if (!await confirmAction('Empty entire trash permanently? This cannot be undone.', { title: 'Empty trash', confirmText: 'Empty trash' })) return;
        try {
            const res = await apiFetch(`${API}/api/trash/empty`, { method: 'POST' });
            if (!res) return;
            const data = await res.json();
            if (data.success) {
                showToast('Trash emptied', 'success');
                await loadFiles();
                await loadUserInfo();
            } else {
                showToast(data.error || 'Failed to empty trash', 'error');
            }
        } catch {
            showToast('Failed to empty trash', 'error');
        }
    }

    function openShareModal(targetId, targetName, targetType = 'file') {
        shareTargetId = targetId;
        shareTargetType = targetType;
        const modal = document.getElementById('shareModal');
        const titleEl = document.getElementById('shareModalTitle');
        const nameEl = document.getElementById('shareModalFileName');
        const inputEl = document.getElementById('shareUsername');
        const userDivider = document.getElementById('shareUserDivider');
        const userSection = document.getElementById('shareUserSection');
        const userBtn = document.getElementById('shareToUserBtn');
        const feedback = document.getElementById('shareFeedback');
        const output = document.getElementById('shareLinkOutput');
        const social = document.getElementById('socialShareRow');
        if (titleEl) {
            titleEl.innerHTML = targetType === 'folder'
                ? '<i class="fas fa-folder-open"></i> Share Folder'
                : '<i class="fas fa-share-alt"></i> Share File';
        }
        if (nameEl) nameEl.textContent = targetName;
        if (inputEl) inputEl.value = '';
        if (userDivider) userDivider.style.display = '';
        if (userSection) userSection.style.display = '';
        if (userBtn) userBtn.style.display = '';
        if (output) output.value = '';
        if (social) social.style.display = 'none';
        if (feedback) {
            feedback.className = 'modal-feedback';
            feedback.textContent = '';
        }
        modal.classList.add('open');
    }

    window.closeShareModal = function () {
        document.getElementById('shareModal').classList.remove('open');
        shareTargetId = null;
        shareTargetType = 'file';
    };

    function copyTextPortable(text) {
        if (navigator.clipboard && window.isSecureContext) {
            return navigator.clipboard.writeText(text).then(() => true).catch(() => false);
        }
        const temp = document.createElement('textarea');
        temp.value = text;
        temp.setAttribute('readonly', '');
        temp.style.position = 'fixed';
        temp.style.left = '-9999px';
        document.body.appendChild(temp);
        temp.select();
        temp.setSelectionRange(0, temp.value.length);
        let ok = false;
        try { ok = document.execCommand('copy'); } catch {}
        document.body.removeChild(temp);
        return Promise.resolve(ok);
    }

    function updateSocialShareLinks(link) {
        const encoded = encodeURIComponent(link);
        const fb = document.getElementById('shareFacebook');
        const wa = document.getElementById('shareWhatsapp');
        const ms = document.getElementById('shareMessenger');
        const tg = document.getElementById('shareTelegram');
        if (fb) fb.href = `https://www.facebook.com/sharer/sharer.php?u=${encoded}`;
        if (wa) wa.href = `https://wa.me/?text=${encoded}`;
        if (ms) ms.href = `https://www.facebook.com/dialog/send?app_id=87741124305&link=${encoded}&redirect_uri=${encoded}`;
        if (tg) tg.href = `https://t.me/share/url?url=${encoded}`;
    }

    window.generateShareLink = async function () {
        if (!shareTargetId) return;
        try {
            const endpoint = shareTargetType === 'folder'
                ? `${API}/api/share/folder/link/${shareTargetId}`
                : `${API}/api/share/link/${shareTargetId}`;
            const res = await apiFetch(endpoint, { method: 'POST' });
            if (!res) return;
            const data = await res.json();
            if (data.success) {
                const output = document.getElementById('shareLinkOutput');
                const social = document.getElementById('socialShareRow');
                if (output) output.value = data.share_link;
                updateSocialShareLinks(data.share_link);
                if (social) social.style.display = 'grid';

                const copied = await copyTextPortable(data.share_link);
                if (copied) modalFeedback('Link copied! Valid for 7 days.', 'success');
                else modalFeedback('Link generated. Copy manually from the field.', 'success');
            } else {
                modalFeedback(data.error || 'Failed to generate link', 'error');
            }
        } catch {
            modalFeedback('Connection error', 'error');
        }
    };

    window.shareToUser = async function () {
        const inputEl = document.getElementById('shareUsername');
        const username = inputEl ? inputEl.value.trim() : '';
        if (!username) return modalFeedback('Enter a username', 'error');
        if (!shareTargetId) return;
        try {
            const endpoint = shareTargetType === 'folder'
                ? `${API}/api/share/folder/user/${shareTargetId}`
                : `${API}/api/share/user/${shareTargetId}`;
            const res = await apiFetch(endpoint, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username }),
            });
            if (!res) return;
            const data = await res.json();
            if (data.success) {
                modalFeedback(data.message, 'success');
                if (inputEl) inputEl.value = '';
            } else {
                modalFeedback(data.error || 'Failed to share', 'error');
            }
        } catch {
            modalFeedback('Connection error', 'error');
        }
    };

    function modalFeedback(msg, type) {
        const el = document.getElementById('shareFeedback');
        if (!el) return;
        el.textContent = msg;
        el.className = `modal-feedback ${type}`;
    }

    document.getElementById('shareModal').addEventListener('click', function (e) {
        if (e.target === this) window.closeShareModal();
    });
    document.addEventListener('click', closeCardMenus);

    if (folderModal) {
        folderModal.addEventListener('click', e => {
            if (e.target === folderModal) closeFolderModal();
        });
    }
    if (renameModal) {
        renameModal.addEventListener('click', e => {
            if (e.target === renameModal) closeRenameModal();
        });
    }
    if (infoModal) {
        infoModal.addEventListener('click', e => {
            if (e.target === infoModal) closeInfoModal();
        });
    }

    function showEmpty() {
        const d = document.createElement('div');
        d.className = 'empty-files';
        let title = 'No files here yet';
        let text = 'Create folders or upload files from the New button';
        if (currentFilter === 'shared') {
            title = 'Nothing shared with you yet';
            text = 'Files and folders shared with you will appear here';
        } else if (currentFilter === 'trash') {
            title = 'Trash is empty';
            text = 'Deleted files and folders appear here until permanently removed';
        } else if (currentFilter === 'mine' && currentFolderId) {
            title = 'Folder is empty';
            text = 'Upload files while this folder is open';
        }
        d.innerHTML = `
            <i class="fas fa-folder-open"></i>
            <h3>${title}</h3>
            <p>${text}</p>`;
        fileListContainer.appendChild(d);

        if (dropZone && currentFilter === 'mine') dropZone.style.display = '';
    }

    function updateCount(n) {
        if (fileCountSpan) fileCountSpan.textContent = n + (n === 1 ? ' item' : ' items');
    }

    function showToast(msg, type) {
        const colors = { error: '#B31412', success: '#137333', warning: '#874D00' };
        const bgs = { error: '#FCE8E6', success: '#E6F4EA', warning: '#FEF7E0' };
        const t = document.createElement('div');
        t.style.cssText = `
            position:fixed; bottom:5.5rem; right:1.5rem;
            background:${bgs[type] || '#F8F9FA'};
            color:${colors[type] || '#202124'};
            padding:.75rem 1.1rem; border-radius:.75rem;
            font-size:.85rem; font-weight:500;
            box-shadow:0 4px 16px rgba(0,0,0,.12);
            z-index:2000; max-width:320px;
            border-left:3px solid ${colors[type] || '#9AA0A6'};`;
        t.textContent = msg;
        document.body.appendChild(t);
        setTimeout(() => t.remove(), 4000);
    }

    function formatSize(bytes) {
        if (!bytes || bytes === 0) return '0 B';
        const k = 1024, sizes = ['B', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
    }

    function fileIcon(name) {
        const ext = name.split('.').pop().toLowerCase();
        if (['jpg', 'jpeg', 'png', 'gif', 'svg', 'webp', 'bmp'].includes(ext)) return 'fa-file-image';
        if (['pdf'].includes(ext)) return 'fa-file-pdf';
        if (['doc', 'docx', 'txt', 'rtf', 'odt', 'md'].includes(ext)) return 'fa-file-lines';
        if (['xls', 'xlsx', 'csv'].includes(ext)) return 'fa-file-excel';
        if (['ppt', 'pptx'].includes(ext)) return 'fa-file-powerpoint';
        if (['zip', 'rar', '7z', 'tar', 'gz', 'bz2'].includes(ext)) return 'fa-file-zipper';
        if (['mp3', 'wav', 'ogg', 'flac', 'aac'].includes(ext)) return 'fa-file-audio';
        if (['mp4', 'avi', 'mov', 'mkv', 'webm'].includes(ext)) return 'fa-file-video';
        if (['c', 'cpp', 'h', 'py', 'java', 'js', 'ts', 'go', 'rs', 'rb', 'cs',
            'html', 'css', 'json', 'yaml', 'toml', 'sh', 'bash', 'sql'].includes(ext)) return 'fa-file-code';
        return 'fa-file';
    }

    function cardTypeClass(ext) {
        if (['jpg', 'jpeg', 'png', 'gif', 'svg', 'webp', 'bmp'].includes(ext)) return 'type-image';
        if (['pdf'].includes(ext)) return 'type-pdf';
        if (['doc', 'docx', 'txt', 'rtf', 'odt', 'md'].includes(ext)) return 'type-doc';
        if (['xls', 'xlsx', 'csv'].includes(ext)) return 'type-data';
        if (['zip', 'rar', '7z', 'tar', 'gz', 'bz2'].includes(ext)) return 'type-archive';
        if (['mp3', 'wav', 'ogg', 'flac', 'aac', 'mp4', 'avi', 'mov', 'mkv', 'webm'].includes(ext)) return 'type-media';
        return 'type-code';
    }

    let dragCount = 0;
    document.addEventListener('dragenter', e => {
        if (e.dataTransfer && e.dataTransfer.types.includes('Files')) {
            e.preventDefault();
            dragCount++;
            if (dragOverlay) dragOverlay.classList.add('active');
        }
    });
    document.addEventListener('dragleave', () => {
        dragCount = Math.max(0, dragCount - 1);
        if (dragCount === 0 && dragOverlay) dragOverlay.classList.remove('active');
    });
    document.addEventListener('dragover', e => e.preventDefault());
    document.addEventListener('drop', e => {
        e.preventDefault();
        dragCount = 0;
        if (dragOverlay) dragOverlay.classList.remove('active');
        if (e.dataTransfer.files.length && currentFilter !== 'trash' && currentFilter !== 'shared') {
            uploadFiles(e.dataTransfer.files);
        }
    });

    if (dropZone) dropZone.addEventListener('click', () => fileInput.click());

    const sidebarNewBtn = document.getElementById('sidebarNewBtn');
    if (sidebarNewBtn) sidebarNewBtn.addEventListener('click', () => fileInput.click());
    if (newFolderBtn) newFolderBtn.addEventListener('click', openFolderModal);
    if (emptyTrashBtn) emptyTrashBtn.addEventListener('click', emptyTrash);
    if (folderBackBtn) folderBackBtn.addEventListener('click', () => {
        currentFolderId = null;
        renderFiles();
    });
    if (createFolderConfirmBtn) createFolderConfirmBtn.addEventListener('click', createFolder);
    if (folderModalCancelBtn) folderModalCancelBtn.addEventListener('click', closeFolderModal);
    if (renameConfirmBtn) renameConfirmBtn.addEventListener('click', doRename);
    if (renameCancelBtn) renameCancelBtn.addEventListener('click', closeRenameModal);
    if (infoCloseBtn) infoCloseBtn.addEventListener('click', closeInfoModal);

    if (folderNameInput) {
        folderNameInput.addEventListener('keydown', e => {
            if (e.key === 'Enter') createFolder();
            if (e.key === 'Escape') closeFolderModal();
        });
    }
    if (renameNameInput) {
        renameNameInput.addEventListener('keydown', e => {
            if (e.key === 'Enter') doRename();
            if (e.key === 'Escape') closeRenameModal();
        });
    }

    if (fileInput) {
        fileInput.addEventListener('change', e => {
            if (e.target.files.length) uploadFiles(e.target.files);
            fileInput.value = '';
        });
    }

    if (clearAllBtn) clearAllBtn.addEventListener('click', clearAll);

    document.querySelectorAll('.nav-item').forEach(item => {
        item.addEventListener('click', e => {
            e.preventDefault();
            document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
            item.classList.add('active');
            currentFilter = item.dataset.filter;
            if (currentFilter !== 'mine') currentFolderId = null;
            renderFiles();
        });
    });

    if (searchInput) {
        searchInput.addEventListener('input', e => {
            searchQuery = e.target.value.toLowerCase().trim();
            renderFiles();
        });
    }

    loadUserInfo();
    loadFiles();
})();
