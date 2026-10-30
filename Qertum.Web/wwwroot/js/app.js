// The web UI's only script besides Blazor's own. It lives in a file, not inline in App.razor, so the
// Content-Security-Policy can allow scripts from 'self' only (UseQertumSecurityHeaders). copyText and
// downloadFile are called by name through JS interop, so they stay global.

document.addEventListener('click', function (e) {
    // Close an open user menu when the click lands outside it.
    document.querySelectorAll('details.user-menu[open]').forEach(function (d) {
        if (!d.contains(e.target)) { d.removeAttribute('open'); }
    });
    // On narrow screens a click in the navigation closes it (the checkbox is the menu's open state).
    if (e.target instanceof Element && e.target.closest('.nav-scrollable')) {
        const toggler = document.querySelector('.navbar-toggler');
        if (toggler) { toggler.click(); }
    }
});

async function copyText(text) {
    // The Clipboard API needs a secure context; fall back so an http:// deployment still copies.
    try {
        await navigator.clipboard.writeText(text);
        return true;
    } catch {
        const ta = document.createElement('textarea');
        ta.value = text;
        ta.setAttribute('readonly', '');
        ta.style.position = 'fixed';
        ta.style.opacity = '0';
        document.body.appendChild(ta);
        ta.select();
        const ok = document.execCommand('copy');
        document.body.removeChild(ta);
        return ok;
    }
}

function downloadFile(filename, mimeType, base64) {
    const bytes = atob(base64);
    const arr = new Uint8Array(bytes.length);
    for (let i = 0; i < bytes.length; i++) arr[i] = bytes.charCodeAt(i);
    const blob = new Blob([arr], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(() => URL.revokeObjectURL(url), 100);
}
