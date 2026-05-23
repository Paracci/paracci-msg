// Paracci - Standalone Preview Runtime

(() => {
    const MAX_TEXT_CHARS = 50000;
    const IMAGE_EXTS = new Set(["png", "jpg", "jpeg", "gif", "webp", "bmp", "svg", "ico"]);
    const VIDEO_EXTS = new Set(["mp4", "webm", "mov"]);
    const AUDIO_EXTS = new Set(["mp3", "wav", "ogg", "flac", "aac", "m4a"]);
    const TEXT_EXTS = new Set(["txt", "log", "csv"]);
    const CODE_EXTS = new Set(["json", "xml", "html", "py", "js", "css"]);
    const objectUrls = [];

    let config = {
        token: "",
        filename: "attachment.bin",
        mimeType: "application/octet-stream",
        fileSize: 0,
        contentUrl: "",
        mediaUrl: "",
        downloadUrl: "",
        allowDownload: true
    };

    let _currentDownloadPath = null;

    function clearPreviewDomState() {
        document.querySelectorAll("video, audio").forEach(media => {
            try {
                media.pause();
                media.removeAttribute("src");
                media.load();
            } catch (error) {
                // Best-effort cleanup before closing or unloading.
            }
        });
        document.querySelectorAll("img").forEach(img => {
            img.removeAttribute("src");
            img.alt = "";
        });
        for (const url of objectUrls.splice(0)) {
            URL.revokeObjectURL(url);
        }
    }

    function readConfig() {
        const configEl = document.getElementById("previewConfig");
        const dataset = configEl ? configEl.dataset : {};
        config = {
            token: dataset.token || "",
            filename: dataset.filename || "attachment.bin",
            mimeType: dataset.mimeType || "application/octet-stream",
            fileSize: Number(dataset.fileSize || 0),
            contentUrl: dataset.contentUrl || "",
            mediaUrl: dataset.mediaUrl || "",
            downloadUrl: dataset.downloadUrl || "",
            allowDownload: dataset.allowDownload !== "false"
        };
    }

    function formatFileSize(bytes) {
        if (bytes < 1024) return bytes + " B";
        if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + " KB";
        if (bytes < 1024 * 1024 * 1024) return (bytes / (1024 * 1024)).toFixed(1) + " MB";
        return (bytes / (1024 * 1024 * 1024)).toFixed(2) + " GB";
    }

    function formatTime(seconds) {
        if (!Number.isFinite(seconds) || seconds < 0) return "0:00";
        const total = Math.floor(seconds);
        const hours = Math.floor(total / 3600);
        const mins = Math.floor((total % 3600) / 60);
        const secs = String(total % 60).padStart(2, "0");
        if (hours > 0) {
            return `${hours}:${String(mins).padStart(2, "0")}:${secs}`;
        }
        return `${mins}:${secs}`;
    }

    function contentUrl() {
        if (config.contentUrl) return config.contentUrl;
        if (config.mediaUrl) return config.mediaUrl;
        return "";
    }

    function downloadUrl() {
        if (!config.allowDownload) return "";
        if (config.downloadUrl) return config.downloadUrl;
        const url = contentUrl();
        if (!url) return "";
        const next = new URL(url, window.location.href);
        next.searchParams.set("download", "1");
        return next.toString();
    }

    function extension() {
        const clean = String(config.filename || "").split(/[?#]/)[0].toLowerCase();
        const dot = clean.lastIndexOf(".");
        return dot >= 0 ? clean.slice(dot + 1) : "";
    }

    function mimeType() {
        return String(config.mimeType || "").toLowerCase();
    }

    function previewKind() {
        const ext = extension();
        const mime = mimeType();
        if (mime === "application/pdf" || ext === "pdf") return "pdf";
        if (mime.startsWith("image/") || IMAGE_EXTS.has(ext)) return "image";
        if (mime.startsWith("video/") || VIDEO_EXTS.has(ext)) return "video";
        if (mime.startsWith("audio/") || AUDIO_EXTS.has(ext)) return "audio";
        if (ext === "md" || mime === "text/markdown") return "markdown";
        if (TEXT_EXTS.has(ext) || mime === "text/plain" || mime === "text/csv") return "text";
        if (CODE_EXTS.has(ext) || mime.includes("json") || mime.includes("xml")) return "code";
        return "unsupported";
    }

    function host() {
        return document.getElementById("contentHost");
    }

    function setDetails(value) {
        const detailsText = document.getElementById("detailsText");
        if (detailsText) detailsText.textContent = value || "";
    }

    function resetHost() {
        host()?.replaceChildren();
    }

    function createObjectUrl(blob) {
        const url = URL.createObjectURL(blob);
        objectUrls.push(url);
        return url;
    }

    function showState(title, copy, actions = []) {
        resetHost();
        const state = document.createElement("div");
        state.className = "message-state";

        const heading = document.createElement("h1");
        heading.className = "state-title";
        heading.textContent = title;
        state.appendChild(heading);

        if (copy) {
            const paragraph = document.createElement("p");
            paragraph.className = "state-copy";
            paragraph.textContent = copy;
            state.appendChild(paragraph);
        }

        const filename = document.createElement("p");
        filename.className = "state-copy";
        filename.textContent = `${config.filename || "attachment.bin"} - ${formatFileSize(Number(config.fileSize || 0))}`;
        state.appendChild(filename);

        if (actions.length) {
            const actionRow = document.createElement("div");
            actionRow.className = "state-actions";
            actions.forEach(action => actionRow.appendChild(action));
            state.appendChild(actionRow);
        }

        host()?.appendChild(state);
    }

    function showDownloadSuccess(filename, path) {
        if (path) {
            _currentDownloadPath = path;
        }

        // For backwards compatibility/tests
        let legacyToast = document.getElementById("downloadSuccessToast");
        if (!legacyToast) {
            legacyToast = document.createElement("div");
            legacyToast.id = "downloadSuccessToast";
            legacyToast.className = "download-success-toast";
            legacyToast.setAttribute("role", "status");
            legacyToast.setAttribute("aria-live", "polite");
            document.body.appendChild(legacyToast);
        }
        legacyToast.textContent = `✓ Saved to Downloads: ${filename || "attachment"}`;
        legacyToast.classList.add("show");
        window.clearTimeout(showDownloadSuccess.timer);
        showDownloadSuccess.timer = window.setTimeout(() => {
            legacyToast.classList.remove("show");
        }, 3000);

        // Slide in the new custom toast
        const toast = document.getElementById("download-toast");
        const label = document.getElementById("toast-filename");
        if (toast && label) {
            label.textContent = filename || "attachment";
            toast.classList.add("active");
            window.clearTimeout(toast._timer);
            toast._timer = window.setTimeout(() => {
                toast.classList.remove("active");
            }, 8000);
        }
    }

    function handleToastClick() {
        if (_currentDownloadPath && window.pywebview?.api) {
            window.pywebview.api.open_file_location(_currentDownloadPath);
            document.getElementById("download-toast")?.classList.remove("active");
        }
    }

    function closeButton() {
        const button = document.createElement("button");
        button.type = "button";
        button.className = "btn";
        button.textContent = "Close";
        button.addEventListener("click", handleClose);
        return button;
    }

    function downloadButton(primary = false) {
        const button = document.createElement("button");
        button.type = "button";
        button.className = primary ? "btn btn-primary" : "btn";
        button.textContent = "Download";
        button.hidden = !config.allowDownload;
        button.addEventListener("click", handleDownload);
        return button;
    }

    function showExpired() {
        showState("This preview has expired. Please reopen the message.", "", [closeButton()]);
    }

    function showLoadError() {
        showState("Could not load preview content.", "", [closeButton()]);
    }

    function showResponseError(response, kind = previewKind()) {
        if (response.status === 404) {
            showExpired();
            return true;
        }
        if (!response.ok) {
            showLoadError();
            return true;
        }
        return false;
    }

    function showUnsupported() {
        const actions = [];
        if (downloadUrl()) actions.push(downloadButton(true));
        actions.push(closeButton());
        showState("Preview not available for this file type.", "", actions);
    }

    function showPdfFallback() {
        const actions = [];
        if (downloadUrl()) actions.push(downloadButton(true));
        actions.push(closeButton());
        showState("PDF preview unavailable. Click Download to open the file.", "", actions);
    }

    async function fetchContent(asText = false) {
        const url = contentUrl();
        if (!url) {
            showUnsupported();
            throw new Error("Preview content URL missing.");
        }

        let response;
        try {
            response = await fetch(url, { cache: "no-store" });
        } catch (error) {
            showLoadError();
            throw error;
        }

        if (showResponseError(response, previewKind())) {
            throw new Error(`Preview fetch failed: ${response.status}`);
        }
        return asText ? response.text() : response.blob();
    }

    function mediaTypeFor(kind) {
        const mime = mimeType();
        if (mime && mime !== "application/octet-stream") return mime;
        const ext = extension();
        const map = {
            mp4: "video/mp4",
            webm: "video/webm",
            mov: "video/quicktime",
            mp3: "audio/mpeg",
            wav: "audio/wav",
            ogg: "audio/ogg",
            flac: "audio/flac",
            aac: "audio/aac",
            m4a: "audio/mp4"
        };
        return map[ext] || (kind === "video" ? "video/mp4" : "audio/mpeg");
    }

    function customMediaPlayer(media, kind) {
        media.controls = false;
        media.autoplay = false;
        media.loop = false;
        media.preload = "metadata";
        media.className = kind === "video" ? "custom-media preview-video" : "custom-media audio-media";

        const shell = document.createElement("div");
        shell.id = "media-container";
        shell.className = `media-shell ${kind}-shell`;

        const controls = document.createElement("div");
        controls.className = "media-controls";

        const play = document.createElement("button");
        play.type = "button";
        play.className = "media-btn";
        play.setAttribute("aria-label", "Play or pause");
        play.title = "Play";
        play.textContent = "▶";

        const time = document.createElement("span");
        time.className = "media-time";
        time.textContent = "0:00 / 0:00";

        const progress = document.createElement("input");
        progress.type = "range";
        progress.className = "media-progress";
        progress.min = "0";
        progress.max = "1000";
        progress.value = "0";
        progress.setAttribute("aria-label", "Seek");

        const volume = document.createElement("input");
        volume.type = "range";
        volume.className = "volume-slider";
        volume.min = "0";
        volume.max = "1";
        volume.step = "0.01";
        volume.value = "1";
        volume.setAttribute("aria-label", "Volume");

        const fullscreen = document.createElement("button");
        fullscreen.type = "button";
        fullscreen.className = "media-btn";
        fullscreen.setAttribute("aria-label", "Fullscreen");
        fullscreen.id = "fullscreen-btn";
        fullscreen.title = "Fullscreen";
        fullscreen.textContent = "⛶";

        function updateTime() {
            const duration = Number.isFinite(media.duration) ? media.duration : 0;
            const current = Number.isFinite(media.currentTime) ? media.currentTime : 0;
            time.textContent = `${formatTime(current)} / ${formatTime(duration)}`;
            progress.value = duration > 0 ? String(Math.round((current / duration) * 1000)) : "0";
        }

        play.addEventListener("click", () => {
            if (media.paused) {
                media.play().catch(() => setDetails("Playback could not start."));
            } else {
                media.pause();
            }
        });
        media.addEventListener("play", () => {
            play.textContent = "⏸";
            play.title = "Pause";
        });
        media.addEventListener("pause", () => {
            play.textContent = "▶";
            play.title = "Play";
        });
        media.addEventListener("loadedmetadata", updateTime);
        media.addEventListener("timeupdate", updateTime);
        media.addEventListener("durationchange", updateTime);
        progress.addEventListener("input", () => {
            const duration = Number.isFinite(media.duration) ? media.duration : 0;
            if (duration > 0) {
                media.currentTime = (Number(progress.value) / 1000) * duration;
            }
        });
        volume.addEventListener("input", () => {
            media.volume = Number(volume.value);
        });
        function updateFullscreenButton() {
            const active = document.fullscreenElement === shell || document.webkitFullscreenElement === shell;
            fullscreen.textContent = "⛶";
            fullscreen.title = active ? "Exit fullscreen" : "Fullscreen";
            fullscreen.classList.toggle("is-fullscreen", active);
        }

        function toggleFullscreen() {
            if (!document.fullscreenElement && !document.webkitFullscreenElement) {
                const container = document.getElementById("media-container") || shell;
                const request = container.requestFullscreen || container.webkitRequestFullscreen;
                if (request) request.call(container);
                return;
            }
            const exit = document.exitFullscreen || document.webkitExitFullscreen;
            if (exit) exit.call(document);
        }

        fullscreen.addEventListener("click", toggleFullscreen);
        document.addEventListener("fullscreenchange", updateFullscreenButton);
        document.addEventListener("webkitfullscreenchange", updateFullscreenButton);

        controls.append(play, time, progress, volume, fullscreen);
        shell.append(media, controls);
        return shell;
    }

    async function renderImage() {
        const blob = await fetchContent(false);
        const img = document.createElement("img");
        img.className = "preview-image";
        img.alt = config.filename || "Preview image";
        img.src = createObjectUrl(blob);
        img.addEventListener("load", () => {
            setDetails(`${img.naturalWidth} x ${img.naturalHeight}`);
        });
        img.addEventListener("click", () => {
            img.classList.toggle("actual-size");
        });

        const wrap = document.createElement("div");
        wrap.className = "image-wrap";
        wrap.appendChild(img);
        resetHost();
        host()?.appendChild(wrap);
    }

    async function renderVideo() {
        const type = mediaTypeFor("video");
        const probe = document.createElement("video");
        if (type && probe.canPlayType(type) === "") {
            setDetails("This format may not be supported by this preview window.");
        }

        const blob = await fetchContent(false);
        const video = document.createElement("video");
        video.src = createObjectUrl(blob);
        video.addEventListener("loadedmetadata", () => {
            const duration = Number.isFinite(video.duration) ? formatTime(video.duration) : "unknown duration";
            const resolution = video.videoWidth && video.videoHeight ? `${video.videoWidth} x ${video.videoHeight}` : "unknown resolution";
            setDetails(`${duration} - ${resolution}`);
        });
        video.addEventListener("error", () => {
            setDetails("This format may not be supported by this preview window.");
        });

        resetHost();
        host()?.appendChild(customMediaPlayer(video, "video"));
    }

    async function renderAudio() {
        const type = mediaTypeFor("audio");
        const probe = document.createElement("audio");
        if (type && probe.canPlayType(type) === "") {
            setDetails("This format may not be supported by this preview window.");
        }

        const blob = await fetchContent(false);
        const panel = document.createElement("div");
        panel.className = "audio-panel";

        const note = document.createElement("div");
        note.className = "music-note";
        note.setAttribute("aria-hidden", "true");
        note.textContent = "Audio";

        const title = document.createElement("h1");
        title.className = "audio-title";
        title.textContent = config.filename || "Audio preview";

        const audio = document.createElement("audio");
        audio.src = createObjectUrl(blob);
        audio.addEventListener("loadedmetadata", () => {
            setDetails(Number.isFinite(audio.duration) ? formatTime(audio.duration) : "");
        });
        audio.addEventListener("error", () => {
            setDetails("This format may not be supported by this preview window.");
        });

        panel.append(note, title, customMediaPlayer(audio, "audio"));
        resetHost();
        host()?.appendChild(panel);
    }

    function truncateText(text) {
        if (text.length <= MAX_TEXT_CHARS) {
            return { text, truncated: false };
        }
        return {
            text: text.slice(0, MAX_TEXT_CHARS),
            truncated: true
        };
    }

    function languageForCode() {
        const ext = extension();
        const map = {
            js: "javascript",
            py: "python",
            html: "xml",
            xml: "xml",
            css: "css",
            json: "json"
        };
        return map[ext] || "";
    }

    function renderTextPanel(text, { highlight = false } = {}) {
        const panel = document.createElement("div");
        panel.className = "text-panel";
        const { text: displayText, truncated } = truncateText(text);

        if (truncated) {
            const notice = document.createElement("div");
            notice.className = "truncate-notice";
            notice.textContent = `Showing first ${MAX_TEXT_CHARS.toLocaleString()} characters.`;
            panel.appendChild(notice);
        }

        const grid = document.createElement("div");
        grid.className = "text-grid";

        const lines = displayText.split("\n");
        const numbers = document.createElement("pre");
        numbers.className = "line-numbers";
        numbers.textContent = lines.map((_, index) => String(index + 1)).join("\n");

        const pre = document.createElement("pre");
        pre.className = "code-pre";
        const code = document.createElement("code");
        const language = languageForCode();

        code.textContent = displayText;
        if (highlight) {
            if (language) code.className = `language-${language}`;
            hljs.highlightElement(code);
        }

        pre.appendChild(code);
        grid.append(numbers, pre);
        panel.appendChild(grid);
        resetHost();
        host()?.appendChild(panel);
    }

    async function renderText() {
        const text = await fetchContent(true);
        renderTextPanel(text);
    }

    async function renderCode() {
        let text = await fetchContent(true);
        if (extension() === "json" || mimeType().includes("json")) {
            try {
                text = JSON.stringify(JSON.parse(text), null, 2);
            } catch (error) {
                // Keep original text when JSON is malformed.
            }
        }
        renderTextPanel(text, { highlight: true });
    }

    function sanitizeMarkdownHtml(html) {
        const template = document.createElement("template");
        template.innerHTML = html;
        const allowedTags = new Set([
            "A", "P", "BR", "STRONG", "B", "EM", "I", "CODE", "PRE",
            "BLOCKQUOTE", "UL", "OL", "LI", "H1", "H2", "H3", "H4",
            "H5", "H6", "HR", "TABLE", "THEAD", "TBODY", "TR", "TH", "TD"
        ]);

        function clean(node) {
            for (const child of Array.from(node.childNodes)) {
                if (child.nodeType === Node.COMMENT_NODE) {
                    child.remove();
                    continue;
                }
                if (child.nodeType !== Node.ELEMENT_NODE) continue;
                if (!allowedTags.has(child.tagName)) {
                    child.replaceWith(document.createTextNode(child.textContent || ""));
                    continue;
                }

                for (const attr of Array.from(child.attributes)) {
                    const name = attr.name.toLowerCase();
                    if (child.tagName === "A" && name === "href") {
                        try {
                            const target = new URL(attr.value, window.location.href);
                            if (!["http:", "https:", "mailto:"].includes(target.protocol)) {
                                child.removeAttribute(attr.name);
                            }
                        } catch (error) {
                            child.removeAttribute(attr.name);
                        }
                    } else if (!(child.tagName === "A" && name === "title")) {
                        child.removeAttribute(attr.name);
                    }
                }

                if (child.tagName === "A" && child.hasAttribute("href")) {
                    child.setAttribute("target", "_blank");
                    child.setAttribute("rel", "noopener noreferrer");
                }
                clean(child);
            }
        }

        clean(template.content);
        return template.innerHTML;
    }

    async function renderMarkdown() {
        const text = await fetchContent(true);
        const { text: displayText, truncated } = truncateText(text);
        const body = document.createElement("article");
        body.className = "markdown-body";
        if (truncated) {
            const notice = document.createElement("div");
            notice.className = "truncate-notice";
            notice.textContent = `Showing first ${MAX_TEXT_CHARS.toLocaleString()} characters.`;
            body.appendChild(notice);
        }

        const rendered = marked.parse(displayText);
        const content = document.createElement("div");
        content.innerHTML = sanitizeMarkdownHtml(rendered);
        body.appendChild(content);

        resetHost();
        host()?.appendChild(body);
    }

    async function renderPdf() {
        const url = contentUrl();
        if (!url) {
            showUnsupported();
            return;
        }

        try {
            const probe = await fetch(url, { method: "HEAD", cache: "no-store" });
            if (showResponseError(probe, "pdf")) {
                return;
            }
        } catch (error) {
            showLoadError();
            return;
        }

        const objectEl = document.createElement("object");
        objectEl.className = "pdf-object";
        objectEl.type = "application/pdf";
        objectEl.data = url;
        objectEl.addEventListener("error", showPdfFallback);

        const fallback = document.createElement("div");
        fallback.className = "message-state";
        const fallbackTitle = document.createElement("h1");
        fallbackTitle.className = "state-title";
        fallbackTitle.textContent = "PDF preview unavailable. Click Download to open the file.";
        fallback.appendChild(fallbackTitle);
        if (downloadUrl()) fallback.appendChild(downloadButton(true));
        objectEl.appendChild(fallback);

        resetHost();
        host()?.appendChild(objectEl);
    }

    async function handleClose() {
        clearPreviewDomState();
        const api = window.pywebview?.api;
        if (config.token && typeof api?.close_preview_window === "function") {
            try {
                await api.close_preview_window(config.token);
                return;
            } catch (error) {
                setDetails("Close request failed.");
            }
        }
        window.close();
    }

    async function handleDownload() {
        if (!config.allowDownload) return;
        const api = window.pywebview?.api;
        if (config.token && typeof api?.download_preview_file === "function") {
            try {
                const result = await api.download_preview_file(config.token);
                if (result?.success) {
                    showDownloadSuccess(result.filename || config.filename, result.path);
                    return;
                }
                if (result?.cancelled) return;
                throw new Error(result?.error || "Download failed.");
            } catch (error) {
                setDetails(error.message || "Download failed.");
                return;
            }
        }

        const url = downloadUrl();
        if (!url) return;
        const opened = window.open(url, "_blank", "noopener");
        if (!opened) {
            window.location.href = url;
        }
    }

    async function render() {
        readConfig();
        const titleText = document.getElementById("titleText");
        const sizeText = document.getElementById("sizeText");
        const downloadBtn = document.getElementById("downloadBtn");
        const closeBtn = document.getElementById("closeBtn");

        if (titleText) titleText.textContent = config.filename || "attachment.bin";
        if (sizeText) sizeText.textContent = `- ${formatFileSize(Number(config.fileSize || 0))}`;
        if (downloadBtn) {
            downloadBtn.hidden = !config.allowDownload;
            downloadBtn.addEventListener("click", handleDownload);
        }
        if (closeBtn) closeBtn.addEventListener("click", handleClose);
        document.getElementById("download-toast")?.addEventListener("click", handleToastClick);

        if (!host()) return;

        try {
            const kind = previewKind();
            if (kind === "image") await renderImage();
            else if (kind === "video") await renderVideo();
            else if (kind === "audio") await renderAudio();
            else if (kind === "text") await renderText();
            else if (kind === "markdown") await renderMarkdown();
            else if (kind === "code") await renderCode();
            else if (kind === "pdf") await renderPdf();
            else showUnsupported();
        } catch (error) {
            if (host()?.children.length === 0) {
                showLoadError();
            }
        }
    }

    window.addEventListener("pagehide", clearPreviewDomState);
    window.addEventListener("beforeunload", clearPreviewDomState);
    window.showDownloadSuccess = showDownloadSuccess;
    document.addEventListener("DOMContentLoaded", render);
})();
